use axum::extract::State;
use axum::response::Json;
use serde_json::Value;
use std::sync::Arc;

use crate::config::Config;

/// OIDC Discovery endpoint.
///
/// Returns the OpenID Connect Provider configuration document.
pub async fn discovery(State(config): State<Arc<Config>>) -> Json<Value> {
    let issuer = &config.issuer_url;

    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat",
            "email", "name", "preferred_username"
        ],
        "grant_types_supported": ["authorization_code"],
        "end_session_endpoint": format!("{issuer}/logout"),
    }))
}
