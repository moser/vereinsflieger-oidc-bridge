use serde::Deserialize;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use std::env;
use std::net::SocketAddr;

/// Top-level configuration file structure.
#[derive(Debug, Deserialize)]
struct ConfigFile {
    server: ServerSection,
    vereinsflieger: VereinsfliegerSection,
    #[serde(rename = "clients")]
    clients: Vec<ClientEntry>,
    branding: Option<BrandingSection>,
}

/// Server configuration from the `[server]` section.
#[derive(Debug, Deserialize)]
struct ServerSection {
    issuer_url: String,
    listen_addr: Option<String>,
    key_path: Option<String>,
    auth_code_ttl: Option<u64>,
    access_token_ttl: Option<u64>,
    session_ttl: Option<u64>,
}

/// Vereinsflieger API configuration from the `[vereinsflieger]` section.
#[derive(Debug, Deserialize)]
struct VereinsfliegerSection {
    appkey: String,
    cid: Option<String>,
}

/// Branding configuration from the optional `[branding]` section.
#[derive(Debug, Deserialize)]
struct BrandingSection {
    title: Option<String>,
    logo_url: Option<String>,
}

/// A registered OAuth2/OIDC client from `[[clients]]`.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    pub client_id: String,
    pub client_secret: String,
    pub allowed_redirect_uris: Vec<String>,
}

/// Branding settings for the login UI.
#[derive(Debug, Clone)]
pub struct Branding {
    /// Organization or service name shown on login pages.
    pub title: String,
    /// Optional URL to a logo image displayed above the login form.
    pub logo_url: Option<String>,
}

/// Application configuration loaded from a TOML file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Vereinsflieger API application key.
    pub vf_appkey: String,
    /// Optional Vereinsflieger club ID.
    pub vf_cid: Option<String>,
    /// Public-facing URL of this service (used as OIDC issuer).
    pub issuer_url: String,
    /// Socket address to bind the server to.
    pub listen_addr: SocketAddr,
    /// Authorization code lifetime in seconds.
    pub auth_code_ttl_secs: u64,
    /// Access token lifetime in seconds.
    pub access_token_ttl_secs: u64,
    /// SSO session lifetime in seconds (default: 8 hours).
    pub session_ttl_secs: u64,
    /// Path to store the RSA signing key.
    pub key_path: String,
    /// Registered clients indexed by client_id for fast lookup.
    clients: HashMap<String, ClientEntry>,
    /// Branding settings for the login UI.
    pub branding: Branding,
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// The file path is taken from the `CONFIG_PATH` environment variable,
    /// defaulting to `/data/config.toml`.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be read or parsed, or if no clients are
    /// configured.
    pub fn load() -> Self {
        let path = env::var("CONFIG_PATH").unwrap_or_else(|_| "/data/config.toml".to_string());
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read config file {path}: {e}"));
        let file: ConfigFile = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse config file {path}: {e}"));

        if file.clients.is_empty() {
            panic!("Config must contain at least one [[clients]] entry");
        }

        let clients: HashMap<String, ClientEntry> = file
            .clients
            .into_iter()
            .map(|c| (c.client_id.clone(), c))
            .collect();

        Self {
            vf_appkey: file.vereinsflieger.appkey,
            vf_cid: file.vereinsflieger.cid.filter(|s| !s.is_empty()),
            issuer_url: file.server.issuer_url.trim_end_matches('/').to_string(),
            listen_addr: file
                .server
                .listen_addr
                .unwrap_or_else(|| "0.0.0.0:8080".to_string())
                .parse()
                .expect("server.listen_addr must be a valid socket address"),
            auth_code_ttl_secs: file.server.auth_code_ttl.unwrap_or(60),
            access_token_ttl_secs: file.server.access_token_ttl.unwrap_or(3600),
            session_ttl_secs: file.server.session_ttl.unwrap_or(28800),
            key_path: file
                .server
                .key_path
                .unwrap_or_else(|| "/data/signing_key.pem".to_string()),
            clients,
            branding: Branding {
                title: file
                    .branding
                    .as_ref()
                    .and_then(|b| b.title.clone())
                    .unwrap_or_else(|| "Vereinsflieger".to_string()),
                logo_url: file.branding.as_ref().and_then(|b| b.logo_url.clone()),
            },
        }
    }

    /// Look up a client by its client_id.
    #[allow(dead_code)]
    pub fn get_client(&self, client_id: &str) -> Option<&ClientEntry> {
        self.clients.get(client_id)
    }

    /// Check whether a client_id is registered.
    pub fn is_valid_client(&self, client_id: &str) -> bool {
        self.clients.contains_key(client_id)
    }

    /// Check whether a redirect URI is allowed for the given client.
    pub fn is_redirect_uri_allowed(&self, client_id: &str, uri: &str) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|c| c.allowed_redirect_uris.iter().any(|allowed| allowed == uri))
    }

    /// Validate client credentials. Returns `true` if the client_id exists
    /// and the secret matches.
    pub fn verify_client_credentials(&self, client_id: &str, client_secret: &str) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|c| {
                c.client_secret
                    .as_bytes()
                    .ct_eq(client_secret.as_bytes())
                    .into()
            })
    }
}
