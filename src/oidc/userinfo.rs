use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use std::sync::Arc;
use tracing::warn;

use crate::jwt::SigningKeys;

/// GET /userinfo - Return the authenticated user's profile claims.
pub async fn userinfo(State(keys): State<Arc<SigningKeys>>, headers: HeaderMap) -> Response {
    // Extract Bearer token from Authorization header
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            warn!("Missing or invalid Authorization header on /userinfo");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Missing or invalid Bearer token",
                })),
            )
                .into_response();
        }
    };

    // Decode and verify the access token
    match keys.decode_access_token(token) {
        Ok(claims) => {
            Json(serde_json::json!({
                "sub": claims.sub,
                "email": claims.email,
                "name": claims.name,
                "preferred_username": claims.preferred_username,
            }))
            .into_response()
        }
        Err(e) => {
            warn!("Invalid or expired access token on /userinfo: {e}");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Token is invalid or expired",
                })),
            )
                .into_response()
        }
    }
}

/// Extract the Bearer token from an Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}
