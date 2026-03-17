mod config;
mod jwt;
mod oidc;
mod store;
mod vf_client;

use axum::extract::Request;
use axum::http::header;
use axum::middleware::{self, Next};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;

use config::Config;
use jwt::SigningKeys;
use oidc::authorize::AppState;
use oidc::token::TokenState;
use store::Store;
use vf_client::VfClient;

fn build_csp(config: &Config) -> header::HeaderValue {
    let img_src = match &config.branding.logo_url {
        Some(url) => {
            let origin = url::Url::parse(url)
                .ok()
                .map(|u| format!("{}://{}", u.scheme(), u.authority()));
            match origin {
                Some(o) => format!("img-src {o};"),
                None => String::new(),
            }
        }
        None => String::new(),
    };

    format!(
        "default-src 'none'; style-src 'unsafe-inline'; {img_src} frame-ancestors 'none'"
    )
    .parse()
    .unwrap()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let config = Arc::new(Config::load());
    info!("Issuer URL: {}", config.issuer_url);
    info!("Listening on: {}", config.listen_addr);

    let keys = Arc::new(SigningKeys::load_or_generate(&config.key_path, &config.issuer_url));
    info!("Signing key ID: {}", keys.kid());

    let store = Arc::new(Store::new(config.auth_code_ttl_secs));

    // Background cleanup for auth codes and 2FA sessions
    let cleanup_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_store.cleanup();
        }
    });

    let vf_client = Arc::new(VfClient::new(
        config.vf_appkey.clone(),
        config.vf_cid.clone(),
    ));

    let app_state = Arc::new(AppState {
        config: config.clone(),
        store: store.clone(),
        keys: keys.clone(),
        vf_client: vf_client.clone(),
    });

    let token_state = Arc::new(TokenState {
        config: config.clone(),
        store: store.clone(),
        keys: keys.clone(),
    });

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc::discovery::discovery),
        )
        .with_state(config.clone())
        .merge(Router::new().route("/jwks", get(oidc::jwks::jwks)).with_state(keys.clone()))
        .merge(
            Router::new()
                .route("/authorize", get(oidc::authorize::authorize_get))
                .route("/authorize", post(oidc::authorize::authorize_post))
                .route("/authorize/2fa", post(oidc::authorize::authorize_2fa_post))
                .route("/authorize/continue", post(oidc::authorize::authorize_continue))
                .route("/logout", get(oidc::authorize::logout))
                .with_state(app_state),
        )
        .merge(
            Router::new()
                .route("/token", post(oidc::token::token_exchange))
                .with_state(token_state),
        )
        .merge(
            Router::new()
                .route("/userinfo", get(oidc::userinfo::userinfo))
                .with_state(keys.clone()),
        )
        .route("/health", get(|| async { "OK" }))
        .layer(middleware::from_fn({
            let csp = build_csp(&config);
            move |request: Request, next: Next| {
                let csp = csp.clone();
                async move {
                    let mut response = next.run(request).await;
                    response
                        .headers_mut()
                        .insert(header::CONTENT_SECURITY_POLICY, csp);
                    response
                }
            }
        }))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .expect("Failed to bind to listen address");

    info!("vf-oidc-bridge is ready");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
