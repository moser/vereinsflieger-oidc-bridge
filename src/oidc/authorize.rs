use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

use crate::config::{Branding, Config};
use crate::jwt::{self, SessionClaims, SigningKeys};
use crate::store::{Store, TwoFactorSession};
use crate::vf_client::{SigninResult, VfClient, VfUserProfile};

const SESSION_COOKIE: &str = "vf_session";

/// Shared application state passed to authorize handlers.
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub keys: Arc<SigningKeys>,
    pub vf_client: Arc<VfClient>,
}

/// Query parameters for the authorization request (from Outline).
#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

/// Form data from the login page.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

/// Form data from the 2FA page.
#[derive(Debug, Deserialize)]
pub struct TwoFactorForm {
    pub auth_secret: String,
    pub session_id: String,
}

/// Form data from the SSO continue / switch account page.
#[derive(Debug, Deserialize)]
pub struct ContinueForm {
    pub redirect_uri: String,
    pub client_id: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

/// Try to read and verify the SSO session from the cookie. Returns the
/// decoded claims if the cookie is present and the JWT signature + expiry
/// are valid.
fn read_session(keys: &SigningKeys, headers: &HeaderMap) -> Option<SessionClaims> {
    let token = extract_cookie(headers, SESSION_COOKIE)?;
    keys.decode_session(token).ok()
}

/// GET /authorize - Show the login form, or a confirmation page if an SSO
/// session cookie already exists.
pub async fn authorize_get(
    State(app): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
    headers: HeaderMap,
) -> Response {
    let client_id = params.client_id.unwrap_or_default();
    let redirect_uri = params.redirect_uri.unwrap_or_default();
    let response_type = params.response_type.unwrap_or_default();
    let scope = params.scope.unwrap_or_else(|| "openid profile email".to_string());
    let state = params.state;
    let nonce = params.nonce;
    let branding = &app.config.branding;

    if !app.config.is_valid_client(&client_id) {
        return Html(error_page(branding, "Ungültige Client-ID")).into_response();
    }
    if response_type != "code" {
        return Html(error_page(
            branding,
            "Nicht unterstützter Antworttyp. Nur 'code' wird unterstützt.",
        ))
        .into_response();
    }
    if !app.config.is_redirect_uri_allowed(&client_id, &redirect_uri) {
        warn!("Rejected redirect_uri not in allowlist: {redirect_uri}");
        return Html(error_page(branding, "Ungültige Weiterleitungs-URI")).into_response();
    }

    // Check for an existing SSO session in the cookie
    if let Some(session) = read_session(&app.keys, &headers) {
        return Html(continue_page(
            branding,
            &session.name,
            &session.email,
            &redirect_uri,
            &client_id,
            &scope,
            state.as_deref(),
            nonce.as_deref(),
        ))
        .into_response();
    }

    Html(login_page(
        branding,
        &redirect_uri,
        &client_id,
        &scope,
        state.as_deref(),
        nonce.as_deref(),
        None,
    ))
    .into_response()
}

/// POST /authorize - Handle login form submission.
pub async fn authorize_post(
    State(app): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let branding = &app.config.branding;

    if !app.config.is_valid_client(&form.client_id) {
        return Html(error_page(branding, "Ungültige Client-ID")).into_response();
    }
    if !app.config.is_redirect_uri_allowed(&form.client_id, &form.redirect_uri) {
        warn!("Rejected redirect_uri not in allowlist: {}", form.redirect_uri);
        return Html(error_page(branding, "Ungültige Weiterleitungs-URI")).into_response();
    }

    let accesstoken = match app.vf_client.get_access_token().await {
        Ok(t) => t,
        Err(e) => {
            warn!("VF accesstoken error: {e}");
            return Html(login_page(
                branding,
                &form.redirect_uri,
                &form.client_id,
                &form.scope,
                form.state.as_deref(),
                form.nonce.as_deref(),
                Some("Verbindung zu Vereinsflieger fehlgeschlagen. Bitte versuchen Sie es erneut."),
            ))
            .into_response();
        }
    };

    let password_hash = crate::vf_client::md5_hash(&form.password);
    let result = match app
        .vf_client
        .signin(&accesstoken, &form.username, &password_hash, None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("VF signin error: {e}");
            return Html(login_page(
                branding,
                &form.redirect_uri,
                &form.client_id,
                &form.scope,
                form.state.as_deref(),
                form.nonce.as_deref(),
                Some("Verbindung zu Vereinsflieger fehlgeschlagen. Bitte versuchen Sie es erneut."),
            ))
            .into_response();
        }
    };

    match result {
        SigninResult::TwoFactorRequired => {
            let session_id = Uuid::new_v4().to_string();
            app.store.insert_2fa_session(
                session_id.clone(),
                TwoFactorSession {
                    vf_accesstoken: accesstoken,
                    username: form.username,
                    password_hash,
                    redirect_uri: form.redirect_uri,
                    client_id: form.client_id,
                    scope: form.scope,
                    state: form.state,
                    nonce: form.nonce,
                    created_at: Instant::now(),
                },
            );
            info!("2FA required, created session {session_id}");
            Html(two_factor_page(branding, &session_id, None)).into_response()
        }
        SigninResult::Failed(msg) => {
            warn!("VF login failed: {msg}");
            app.vf_client.signout(&accesstoken).await;
            Html(login_page(
                branding,
                &form.redirect_uri,
                &form.client_id,
                &form.scope,
                form.state.as_deref(),
                form.nonce.as_deref(),
                Some("Benutzername oder Passwort ungültig."),
            ))
            .into_response()
        }
        SigninResult::Success => {
            complete_auth(
                &app,
                &accesstoken,
                &form.redirect_uri,
                &form.client_id,
                &form.scope,
                form.state.as_deref(),
                form.nonce.as_deref(),
            )
            .await
        }
    }
}

/// POST /authorize/2fa - Handle 2FA form submission.
pub async fn authorize_2fa_post(
    State(app): State<Arc<AppState>>,
    Form(form): Form<TwoFactorForm>,
) -> Response {
    let branding = &app.config.branding;

    let session = match app.store.take_2fa_session(&form.session_id) {
        Some(s) => s,
        None => {
            return Html(error_page(
                branding,
                "Ihre Zwei-Faktor-Sitzung ist abgelaufen. Bitte melden Sie sich erneut an.",
            ))
            .into_response();
        }
    };

    let result = match app
        .vf_client
        .signin(
            &session.vf_accesstoken,
            &session.username,
            &session.password_hash,
            Some(&form.auth_secret),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("VF 2FA signin error: {e}");
            return Html(two_factor_page(
                branding,
                &form.session_id,
                Some("Code konnte nicht überprüft werden. Bitte versuchen Sie es erneut."),
            ))
            .into_response();
        }
    };

    match result {
        SigninResult::Success => {
            complete_auth(
                &app,
                &session.vf_accesstoken,
                &session.redirect_uri,
                &session.client_id,
                &session.scope,
                session.state.as_deref(),
                session.nonce.as_deref(),
            )
            .await
        }
        SigninResult::Failed(msg) => {
            warn!("VF 2FA failed: {msg}");
            let session_id = form.session_id.clone();
            app.store.insert_2fa_session(
                session_id.clone(),
                TwoFactorSession {
                    vf_accesstoken: session.vf_accesstoken,
                    username: session.username,
                    password_hash: session.password_hash,
                    redirect_uri: session.redirect_uri,
                    client_id: session.client_id,
                    scope: session.scope,
                    state: session.state,
                    nonce: session.nonce,
                    created_at: session.created_at,
                },
            );
            Html(two_factor_page(
                branding,
                &session_id,
                Some("Ungültiger Authentifizierungscode."),
            ))
            .into_response()
        }
        SigninResult::TwoFactorRequired => {
            Html(error_page(
                branding,
                "Unerwarteter 2FA-Zustand. Bitte versuchen Sie es erneut.",
            ))
            .into_response()
        }
    }
}

/// POST /authorize/continue - Issue an auth code from an existing SSO session
/// cookie without re-authenticating against the VF API.
pub async fn authorize_continue(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ContinueForm>,
) -> Response {
    let branding = &app.config.branding;

    if !app.config.is_valid_client(&form.client_id) {
        return Html(error_page(branding, "Ungültige Client-ID")).into_response();
    }
    if !app.config.is_redirect_uri_allowed(&form.client_id, &form.redirect_uri) {
        return Html(error_page(branding, "Ungültige Weiterleitungs-URI")).into_response();
    }

    let session = match read_session(&app.keys, &headers) {
        Some(s) => s,
        None => {
            return Html(error_page(
                branding,
                "Sitzung abgelaufen. Bitte melden Sie sich erneut an.",
            ))
            .into_response();
        }
    };

    let user = VfUserProfile {
        uid: session.sub.parse().unwrap_or(0),
        firstname: session.firstname,
        lastname: session.lastname,
        email: session.email,
    };

    issue_code_and_redirect(
        branding,
        &app.store,
        user,
        &form.redirect_uri,
        &form.client_id,
        &form.scope,
        form.state.as_deref(),
        form.nonce.as_deref(),
    )
}

/// GET /logout - Clear the SSO session cookie.
pub async fn logout(State(app): State<Arc<AppState>>) -> Response {
    let branding = &app.config.branding;
    let mut response = Html(render_page(
        "Abgemeldet",
        branding,
        r#"<h1>Abgemeldet</h1>
        <p class="subtitle">Sie wurden erfolgreich abgemeldet.</p>"#,
    ))
    .into_response();

    let secure = if app.config.issuer_url.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().insert(
        "Set-Cookie",
        format!("{SESSION_COOKIE}=; Path=/authorize; Max-Age=0; HttpOnly; SameSite=Lax{secure}")
            .parse()
            .unwrap(),
    );

    response
}

/// Complete the authorization flow after successful VF authentication:
/// fetch user profile, set SSO session cookie, issue auth code, redirect.
async fn complete_auth(
    app: &AppState,
    accesstoken: &str,
    redirect_uri: &str,
    client_id: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
) -> Response {
    let branding = &app.config.branding;

    let user = match app.vf_client.get_user(accesstoken).await {
        Ok(u) => u,
        Err(e) => {
            warn!("VF getuser error: {e}");
            app.vf_client.signout(accesstoken).await;
            return Html(error_page(
                branding,
                "Ihr Profil konnte nicht von Vereinsflieger abgerufen werden.",
            ))
            .into_response();
        }
    };

    app.vf_client.signout(accesstoken).await;

    info!(
        "Auth successful for {} (uid={}), creating SSO session",
        user.email, user.uid
    );

    // Build a signed session JWT for the cookie
    let now = jwt::now_secs();
    let session_claims = SessionClaims {
        sub: user.uid.to_string(),
        exp: now + app.config.session_ttl_secs,
        iat: now,
        email: user.email.clone(),
        name: format!("{} {}", user.firstname, user.lastname)
            .trim()
            .to_string(),
        firstname: user.firstname.clone(),
        lastname: user.lastname.clone(),
    };

    let session_jwt = match app.keys.sign(&session_claims) {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to sign session JWT: {e}");
            return Html(error_page(
                branding,
                "Interner Fehler beim Erstellen der Sitzung.",
            ))
            .into_response();
        }
    };

    // Issue the auth code and build the redirect
    let mut response = issue_code_and_redirect(
        branding,
        &app.store,
        user,
        redirect_uri,
        client_id,
        scope,
        state,
        nonce,
    );

    // Set the SSO session cookie with the signed JWT.
    // Path is restricted to /authorize so the cookie is only sent to the
    // bridge's authorize endpoints and not to other services on the same
    // hostname (cookies are NOT port-scoped).
    let max_age = app.config.session_ttl_secs;
    let secure = if app.config.issuer_url.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().insert(
        "Set-Cookie",
        format!(
            "{SESSION_COOKIE}={session_jwt}; Path=/authorize; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
        )
        .parse()
        .unwrap(),
    );

    response
}

/// Issue an authorization code for the given user and build a redirect
/// response back to the client.
fn issue_code_and_redirect(
    branding: &Branding,
    store: &Store,
    user: VfUserProfile,
    redirect_uri: &str,
    client_id: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
) -> Response {
    let code = Uuid::new_v4().to_string();
    info!("Issuing auth code for {} (uid={})", user.email, user.uid);

    store.insert_auth_code(
        code.clone(),
        user,
        redirect_uri.to_string(),
        client_id.to_string(),
        scope.to_string(),
        nonce.map(|s| s.to_string()),
    );

    let mut redirect_url = match Url::parse(redirect_uri) {
        Ok(u) => u,
        Err(e) => {
            warn!("Failed to parse redirect_uri: {e}");
            return Html(error_page(branding, "Ungültige Weiterleitungs-URI.")).into_response();
        }
    };
    redirect_url.query_pairs_mut().append_pair("code", &code);
    if let Some(s) = state {
        redirect_url.query_pairs_mut().append_pair("state", s);
    }

    // Use 303 See Other so the browser follows with GET, not POST.
    Redirect::to(redirect_url.as_str()).into_response()
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

/// Extract a cookie value from the request headers by name.
fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HTML templates
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion in an HTML attribute value.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#x27;")
}

fn render_page(page_title: &str, branding: &Branding, content: &str) -> String {
    let brand_html = match &branding.logo_url {
        Some(url) => format!(
            r#"<img src="{}" alt="{}" class="logo">"#,
            html_escape(url),
            html_escape(&branding.title),
        ),
        None => format!(
            r#"<div class="brand">{}</div>"#,
            html_escape(&branding.title),
        ),
    };

    let title = html_escape(page_title);
    let brand_title = html_escape(&branding.title);

    format!(
        r#"<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title} – {brand_title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
               background: #f5f7fb; display: flex; justify-content: center; align-items: center;
               min-height: 100vh; color: #333; }}
        .card {{ background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
                 padding: 40px; width: 100%; max-width: 400px; }}
        .logo {{ display: block; max-height: 48px; margin: 0 auto 24px; }}
        .brand {{ text-align: center; font-size: 16px; font-weight: 600; color: #666; margin-bottom: 8px; }}
        h1 {{ font-size: 20px; font-weight: 600; margin-bottom: 24px; text-align: center; }}
        .subtitle {{ font-size: 14px; color: #666; text-align: center; margin-bottom: 24px; }}
        .field {{ margin-bottom: 16px; }}
        label {{ display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; }}
        input[type="text"], input[type="password"] {{
            width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 6px;
            font-size: 15px; outline: none; transition: border-color 0.2s;
        }}
        input.code-input {{ text-align: center; letter-spacing: 4px; font-size: 18px; }}
        input:focus {{ border-color: #4c9ffe; }}
        button, .btn {{ display: block; width: 100%; padding: 12px; background: #4c9ffe; color: #fff; border: none;
                  border-radius: 6px; font-size: 15px; font-weight: 500; cursor: pointer;
                  transition: background 0.2s; text-align: center; text-decoration: none; }}
        button:hover, .btn:hover {{ background: #3a8dee; }}
        .btn-secondary {{ background: #f3f4f6; color: #333; margin-top: 8px; }}
        .btn-secondary:hover {{ background: #e5e7eb; }}
        .user-info {{ text-align: center; margin-bottom: 24px; }}
        .user-info .name {{ font-size: 18px; font-weight: 600; }}
        .user-info .email {{ font-size: 14px; color: #666; margin-top: 4px; }}
        .error {{ background: #fef2f2; color: #b91c1c; padding: 10px 14px; border-radius: 6px;
                  font-size: 14px; margin-bottom: 16px; }}
        .error-page h1 {{ color: #b91c1c; margin-bottom: 16px; }}
        .error-page p {{ font-size: 15px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class="card">
        {brand_html}
        {content}
    </div>
</body>
</html>"#
    )
}

fn login_page(
    branding: &Branding,
    redirect_uri: &str,
    client_id: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
    error: Option<&str>,
) -> String {
    let error_html = error
        .map(|e| format!(r#"<div class="error">{}</div>"#, html_escape(e)))
        .unwrap_or_default();

    let redirect_uri = html_escape(redirect_uri);
    let client_id = html_escape(client_id);
    let scope = html_escape(scope);
    let state_field = state
        .map(|s| format!(r#"<input type="hidden" name="state" value="{}">"#, html_escape(s)))
        .unwrap_or_default();
    let nonce_field = nonce
        .map(|n| format!(r#"<input type="hidden" name="nonce" value="{}">"#, html_escape(n)))
        .unwrap_or_default();

    render_page(
        "Anmelden",
        branding,
        &format!(
            r#"<h1>Anmelden</h1>
        {error_html}
        <form method="POST" action="/authorize">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="scope" value="{scope}">
            {state_field}
            {nonce_field}
            <div class="field">
                <label for="username">Benutzername oder E-Mail</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="field">
                <label for="password">Passwort</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Anmelden</button>
        </form>"#
        ),
    )
}

fn continue_page(
    branding: &Branding,
    name: &str,
    email: &str,
    redirect_uri: &str,
    client_id: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let name = html_escape(name);
    let email = html_escape(email);
    let redirect_uri = html_escape(redirect_uri);
    let client_id = html_escape(client_id);
    let scope = html_escape(scope);
    let state_field = state
        .map(|s| format!(r#"<input type="hidden" name="state" value="{}">"#, html_escape(s)))
        .unwrap_or_default();
    let nonce_field = nonce
        .map(|n| format!(r#"<input type="hidden" name="nonce" value="{}">"#, html_escape(n)))
        .unwrap_or_default();

    render_page(
        "Willkommen zurück",
        branding,
        &format!(
            r#"<h1>Willkommen zurück</h1>
        <div class="user-info">
            <div class="name">{name}</div>
            <div class="email">{email}</div>
        </div>
        <form method="POST" action="/authorize/continue">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="scope" value="{scope}">
            {state_field}
            {nonce_field}
            <button type="submit">Weiter als {name}</button>
        </form>
        <a href="/logout" class="btn btn-secondary">Anderes Konto verwenden</a>"#
        ),
    )
}

fn two_factor_page(branding: &Branding, session_id: &str, error: Option<&str>) -> String {
    let error_html = error
        .map(|e| format!(r#"<div class="error">{}</div>"#, html_escape(e)))
        .unwrap_or_default();
    let session_id = html_escape(session_id);

    render_page(
        "Zwei-Faktor-Authentifizierung",
        branding,
        &format!(
            r#"<h1>Zwei-Faktor-Authentifizierung</h1>
        <p class="subtitle">Geben Sie den Code aus Ihrer Authenticator-App ein.</p>
        {error_html}
        <form method="POST" action="/authorize/2fa">
            <input type="hidden" name="session_id" value="{session_id}">
            <div class="field">
                <label for="auth_secret">Authentifizierungscode</label>
                <input type="text" id="auth_secret" name="auth_secret" class="code-input" required autofocus
                       autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]*">
            </div>
            <button type="submit">Bestätigen</button>
        </form>"#
        ),
    )
}

fn error_page(branding: &Branding, message: &str) -> String {
    let message = html_escape(message);
    render_page(
        "Fehler",
        branding,
        &format!(
            r#"<div class="error-page">
        <h1>Fehler</h1>
        <p>{message}</p>
    </div>"#
        ),
    )
}
