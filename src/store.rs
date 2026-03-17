use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::vf_client::VfUserProfile;

/// Data stored for a pending authorization code.
pub struct AuthCodeEntry {
    pub user: VfUserProfile,
    pub redirect_uri: String,
    #[allow(dead_code)]
    pub client_id: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub created_at: Instant,
}

/// Data stored for a pending 2FA session.
pub struct TwoFactorSession {
    pub vf_accesstoken: String,
    pub username: String,
    pub password_hash: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub created_at: Instant,
}

/// In-memory store for authorization codes and 2FA sessions.
///
/// Entries are checked for expiration on read, and a background task
/// periodically cleans up expired entries to avoid memory leaks.
///
/// SSO sessions are stored entirely in signed JWT cookies and require
/// no server-side state.
pub struct Store {
    auth_codes: Mutex<HashMap<String, AuthCodeEntry>>,
    two_factor_sessions: Mutex<HashMap<String, TwoFactorSession>>,
    auth_code_ttl_secs: u64,
    two_factor_ttl_secs: u64,
}

impl Store {
    /// Create a new store with the given TTL values.
    pub fn new(auth_code_ttl_secs: u64) -> Self {
        Self {
            auth_codes: Mutex::new(HashMap::new()),
            two_factor_sessions: Mutex::new(HashMap::new()),
            auth_code_ttl_secs,
            two_factor_ttl_secs: 300,
        }
    }

    /// Store an authorization code with its associated user profile.
    pub fn insert_auth_code(
        &self,
        code: String,
        user: VfUserProfile,
        redirect_uri: String,
        client_id: String,
        scope: String,
        nonce: Option<String>,
    ) {
        let mut map = self.auth_codes.lock().unwrap();
        map.insert(
            code,
            AuthCodeEntry {
                user,
                redirect_uri,
                client_id,
                scope,
                nonce,
                created_at: Instant::now(),
            },
        );
    }

    /// Consume an authorization code, returning the entry if valid and not
    /// expired.
    pub fn take_auth_code(&self, code: &str) -> Option<AuthCodeEntry> {
        let mut map = self.auth_codes.lock().unwrap();
        let entry = map.remove(code)?;
        if entry.created_at.elapsed().as_secs() > self.auth_code_ttl_secs {
            return None;
        }
        Some(entry)
    }

    /// Store a two-factor authentication session.
    pub fn insert_2fa_session(&self, session_id: String, session: TwoFactorSession) {
        let mut map = self.two_factor_sessions.lock().unwrap();
        map.insert(session_id, session);
    }

    /// Consume a 2FA session. Returns `None` if expired or not found.
    pub fn take_2fa_session(&self, session_id: &str) -> Option<TwoFactorSession> {
        let mut map = self.two_factor_sessions.lock().unwrap();
        let entry = map.remove(session_id)?;
        if entry.created_at.elapsed().as_secs() > self.two_factor_ttl_secs {
            return None;
        }
        Some(entry)
    }

    /// Periodically called by a background task to clean up expired entries.
    pub fn cleanup(&self) {
        {
            let mut map = self.auth_codes.lock().unwrap();
            map.retain(|_, v| v.created_at.elapsed().as_secs() <= self.auth_code_ttl_secs);
        }
        {
            let mut map = self.two_factor_sessions.lock().unwrap();
            map.retain(|_, v| v.created_at.elapsed().as_secs() <= self.two_factor_ttl_secs);
        }
    }
}
