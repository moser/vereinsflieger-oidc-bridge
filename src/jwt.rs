use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// RSA key pair used for signing JWTs.
pub struct SigningKeys {
    private_key: RsaPrivateKey,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    kid: String,
    issuer: String,
}

impl SigningKeys {
    /// Load an existing RSA key from disk, or generate a new one and save it.
    pub fn load_or_generate(path: &str, issuer: &str) -> Self {
        let private_key = if Path::new(path).exists() {
            info!("Loading RSA signing key from {path}");
            let pem = std::fs::read_to_string(path).expect("Failed to read signing key file");
            rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_pem(&pem)
                .expect("Failed to parse RSA private key PEM")
        } else {
            info!("Generating new RSA signing key at {path}");
            let mut rng = rand::thread_rng();
            let key =
                RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA private key");

            // Ensure parent directory exists
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent).ok();
            }

            let pem = key
                .to_pkcs1_pem(LineEnding::LF)
                .expect("Failed to encode RSA private key as PEM");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .expect("Failed to create signing key file");
            file.write_all(pem.as_bytes())
                .expect("Failed to write signing key file");
            key
        };

        let pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Failed to encode RSA private key");
        let encoding_key =
            EncodingKey::from_rsa_pem(pem.as_bytes()).expect("Failed to create encoding key");

        // Use the public key for decoding
        let pub_pem = private_key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Failed to encode RSA public key");
        let decoding_key =
            DecodingKey::from_rsa_pem(pub_pem.as_bytes()).expect("Failed to create decoding key");

        // Compute a stable key ID from the public key fingerprint
        let pub_der = private_key
            .to_public_key()
            .to_pkcs1_der()
            .expect("Failed to encode public key");
        let mut hasher = Sha256::new();
        hasher.update(pub_der.as_bytes());
        let kid = URL_SAFE_NO_PAD.encode(&hasher.finalize()[..8]);

        Self {
            private_key,
            encoding_key,
            decoding_key,
            kid,
            issuer: issuer.to_string(),
        }
    }

    /// Return the key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Return the JWK representation of the public key for the JWKS endpoint.
    pub fn public_jwk(&self) -> serde_json::Value {
        let pub_key = self.private_key.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

        serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": n,
            "e": e,
        })
    }

    /// Create a signed JWT with the given claims.
    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.encoding_key)
    }

    /// Decode and verify an access token.
    pub fn decode_access_token(
        &self,
        token: &str,
    ) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_issuer(&[&self.issuer]);
        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

/// Standard OIDC ID token claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub email: String,
    pub name: String,
    pub preferred_username: String,
    /// OIDC nonce echoed back from the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Access token claims (opaque JWT).
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub scope: String,
    pub email: String,
    pub name: String,
    pub preferred_username: String,
}

/// SSO session claims stored in a signed cookie. Contains only non-secret
/// user profile data. The signature prevents tampering; the `exp` claim
/// enforces the session lifetime.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub email: String,
    pub name: String,
    pub firstname: String,
    pub lastname: String,
}

impl SigningKeys {
    /// Decode and verify a session cookie JWT.
    pub fn decode_session(
        &self,
        token: &str,
    ) -> Result<SessionClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        let token_data = decode::<SessionClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

/// Return the current UNIX timestamp.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock before UNIX epoch")
        .as_secs()
}
