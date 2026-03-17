use axum::extract::State;
use axum::response::Json;
use serde_json::Value;
use std::sync::Arc;

use crate::jwt::SigningKeys;

/// JWKS endpoint.
///
/// Returns the JSON Web Key Set containing the public signing key.
pub async fn jwks(State(keys): State<Arc<SigningKeys>>) -> Json<Value> {
    Json(serde_json::json!({
        "keys": [keys.public_jwk()]
    }))
}
