use md5::{Digest, Md5};
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

const VF_BASE_URL: &str = "https://www.vereinsflieger.de/interface/rest";

/// User profile returned by the Vereinsflieger API.
#[derive(Debug, Clone)]
pub struct VfUserProfile {
    pub uid: u64,
    pub firstname: String,
    pub lastname: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    accesstoken: Option<String>,
}

/// Result of a sign-in attempt.
pub enum SigninResult {
    /// Authentication succeeded.
    Success,
    /// Two-factor authentication is required.
    TwoFactorRequired,
    /// Authentication failed with an error message.
    Failed(String),
}

/// Client for the Vereinsflieger REST API.
pub struct VfClient {
    http: reqwest::Client,
    appkey: String,
    cid: Option<String>,
}

impl VfClient {
    /// Create a new VF API client.
    pub fn new(appkey: String, cid: Option<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            appkey,
            cid,
        }
    }

    /// Obtain a fresh access token from the VF API.
    pub async fn get_access_token(&self) -> Result<String, String> {
        let resp = self
            .http
            .get(format!("{VF_BASE_URL}/auth/accesstoken"))
            .send()
            .await
            .map_err(|e| format!("Failed to reach Vereinsflieger API: {e}"))?;

        let data: AccessTokenResponse = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response from VF accesstoken: {e}"))?;

        match data.accesstoken {
            Some(token) if !token.is_empty() => Ok(token),
            _ => Err("Failed to obtain VF access token".to_string()),
        }
    }

    /// Sign in to the VF API with the given credentials.
    ///
    /// The VF API returns fields with inconsistent types, so we parse the
    /// response as raw JSON.
    pub async fn signin(
        &self,
        accesstoken: &str,
        username: &str,
        password_hash: &str,
        auth_secret: Option<&str>,
    ) -> Result<SigninResult, String> {
        let mut params = vec![
            ("accesstoken", accesstoken.to_string()),
            ("appkey", self.appkey.clone()),
            ("username", username.to_string()),
            ("password", password_hash.to_string()),
        ];

        if let Some(cid) = &self.cid {
            params.push(("cid", cid.clone()));
        }
        if let Some(secret) = auth_secret {
            params.push(("auth_secret", secret.to_string()));
        }

        let resp = self
            .http
            .post(format!("{VF_BASE_URL}/auth/signin"))
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Failed to reach VF signin: {e}"))?;

        let data: Value = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response from VF signin: {e}"))?;

        if json_as_u64(&data, "need_2fa").unwrap_or(0) == 1 {
            return Ok(SigninResult::TwoFactorRequired);
        }

        let status = json_as_u64(&data, "httpstatuscode").unwrap_or(0);
        if status != 200 {
            let msg = data["error"]
                .as_str()
                .unwrap_or("Invalid username or password");
            return Ok(SigninResult::Failed(msg.to_string()));
        }

        Ok(SigninResult::Success)
    }

    /// Fetch the authenticated user's profile.
    ///
    /// The VF API returns fields with inconsistent types (e.g. numeric IDs as
    /// strings), so we parse the response as raw JSON and extract fields
    /// leniently.
    pub async fn get_user(&self, accesstoken: &str) -> Result<VfUserProfile, String> {
        let params = [("accesstoken", accesstoken)];

        let resp = self
            .http
            .post(format!("{VF_BASE_URL}/auth/getuser"))
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Failed to reach VF getuser: {e}"))?;

        let data: Value = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response from VF getuser: {e}"))?;

        info!("VF getuser raw response keys: {:?}", data.as_object().map(|o| o.keys().collect::<Vec<_>>()));

        let status = json_as_u64(&data, "httpstatuscode").unwrap_or(0);
        if status != 200 {
            let msg = data["error"]
                .as_str()
                .unwrap_or("Failed to retrieve user profile");
            return Err(msg.to_string());
        }

        let email = json_as_string(&data, "email").unwrap_or_default();
        if email.is_empty() {
            return Err("User profile has no email address".to_string());
        }

        Ok(VfUserProfile {
            uid: json_as_u64(&data, "uid").unwrap_or(0),
            firstname: json_as_string(&data, "firstname").unwrap_or_default(),
            lastname: json_as_string(&data, "lastname").unwrap_or_default(),
            email,
        })
    }

    /// Sign out of the VF API to clean up the server-side session.
    pub async fn signout(&self, accesstoken: &str) {
        let params = [("accesstoken", accesstoken)];

        match self
            .http
            .delete(format!("{VF_BASE_URL}/auth/signout"))
            .form(&params)
            .send()
            .await
        {
            Ok(_) => info!("VF session cleaned up"),
            Err(e) => warn!("Failed to sign out of VF API: {e}"),
        }
    }
}

/// Extract a string value from a JSON object, handling both string and numeric types.
fn json_as_string(value: &Value, key: &str) -> Option<String> {
    match &value[key] {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Extract a u64 value from a JSON object, handling both numeric and string types.
fn json_as_u64(value: &Value, key: &str) -> Option<u64> {
    match &value[key] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Hash a string with MD5.
///
/// NOTE: MD5 is cryptographically broken and should not be used for password
/// hashing in new systems. However, the Vereinsflieger REST API **requires**
/// passwords to be sent as MD5 hex digests. This is a hard requirement of the
/// legacy API and cannot be changed on our side.
pub fn md5_hash(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}
