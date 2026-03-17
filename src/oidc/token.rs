use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::Form;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::Config;
use crate::jwt::{self, AccessTokenClaims, IdTokenClaims, SigningKeys};
use crate::store::Store;

/// Shared state for the token endpoint.
pub struct TokenState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub keys: Arc<SigningKeys>,
}

/// Form data for the token exchange request.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// POST /token - Exchange authorization code for tokens.
///
/// Supports client authentication via both `client_secret_post` (form body)
/// and `client_secret_basic` (Authorization header), as advertised in the
/// discovery document.
pub async fn token_exchange(
    State(state): State<Arc<TokenState>>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Response {
    // Validate grant type
    if form.grant_type.as_deref() != Some("authorization_code") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only authorization_code grant type is supported",
        );
    }

    // Extract client credentials from form body or Authorization: Basic header
    let (client_id, client_secret) =
        extract_client_credentials(&headers, &form);

    if !state.config.verify_client_credentials(&client_id, &client_secret) {
        warn!(
            "Invalid client credentials for token exchange (client_id={client_id})"
        );
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Invalid client credentials",
        );
    }

    // Look up and consume the authorization code
    let code = form.code.as_deref().unwrap_or_default();
    let entry = match state.store.take_auth_code(code) {
        Some(e) => e,
        None => {
            warn!("Invalid or expired authorization code");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid or expired authorization code",
            );
        }
    };

    // Verify the authorization code was issued to this client (RFC 6749 §4.1.3)
    if entry.client_id != client_id {
        warn!(
            "Auth code client_id mismatch: expected={}, got={client_id}",
            entry.client_id
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code was not issued to this client",
        );
    }

    // Validate redirect_uri matches (required per RFC 6749 §4.1.3)
    let redirect_uri = form.redirect_uri.as_deref().unwrap_or_default();
    if redirect_uri != entry.redirect_uri {
        warn!("redirect_uri mismatch in token exchange");
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match the authorization request",
        );
    }

    let now = jwt::now_secs();
    let sub = entry.user.uid.to_string();
    let name = format!("{} {}", entry.user.firstname, entry.user.lastname)
        .trim()
        .to_string();

    // Create access token
    let access_claims = AccessTokenClaims {
        iss: state.config.issuer_url.clone(),
        sub: sub.clone(),
        exp: now + state.config.access_token_ttl_secs,
        iat: now,
        scope: entry.scope.clone(),
        email: entry.user.email.clone(),
        name: name.clone(),
        preferred_username: entry.user.email.clone(),
    };

    let access_token = match state.keys.sign(&access_claims) {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to sign access token: {e}");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create access token",
            );
        }
    };

    // Create ID token with nonce if it was provided in the authorization request
    let id_claims = IdTokenClaims {
        iss: state.config.issuer_url.clone(),
        sub,
        aud: client_id.to_string(),
        exp: now + state.config.access_token_ttl_secs,
        iat: now,
        email: entry.user.email.clone(),
        name,
        preferred_username: entry.user.email.clone(),
        nonce: entry.nonce,
    };

    let id_token = match state.keys.sign(&id_claims) {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to sign id_token: {e}");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create id_token",
            );
        }
    };

    info!("Token exchange successful for {}", entry.user.email);

    let mut response = Json(serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_ttl_secs,
        "id_token": id_token,
        "scope": entry.scope,
    }))
    .into_response();

    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().unwrap());

    response
}

/// Extract client_id and client_secret from either the form body
/// (`client_secret_post`) or the `Authorization: Basic` header
/// (`client_secret_basic`).
fn extract_client_credentials(headers: &HeaderMap, form: &TokenRequest) -> (String, String) {
    // Try form body first
    if let (Some(id), Some(secret)) = (&form.client_id, &form.client_secret) {
        if !id.is_empty() && !secret.is_empty() {
            return (id.clone(), secret.clone());
        }
    }

    // Fall back to Authorization: Basic header
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = STANDARD.decode(encoded.trim()) {
                    if let Ok(credentials) = String::from_utf8(decoded) {
                        if let Some((id, secret)) = credentials.split_once(':') {
                            return (id.to_string(), secret.to_string());
                        }
                    }
                }
            }
        }
    }

    // Return whatever we have from the form (may be empty)
    (
        form.client_id.clone().unwrap_or_default(),
        form.client_secret.clone().unwrap_or_default(),
    )
}

fn error_response(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}
