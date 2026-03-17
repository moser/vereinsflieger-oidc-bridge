# vf-oidc-bridge

An OpenID Connect (OIDC) Identity Provider that authenticates users against the [Vereinsflieger.de](https://www.vereinsflieger.de) REST API. This lets you use Vereinsflieger credentials to log in to any application that supports OIDC (e.g. Nextcloud, Gitea, Authentik).

## How it works

1. An application redirects the user to `/authorize` with a standard OIDC authorization request.
2. The user enters their Vereinsflieger username and password (and 2FA code, if enabled).
3. The bridge authenticates against the Vereinsflieger API, fetches the user profile, and issues a signed ID token + access token.
4. The application exchanges the authorization code for tokens at `/token` and can retrieve user claims from `/userinfo`.

### OIDC endpoints

| Endpoint | Description |
|---|---|
| `/.well-known/openid-configuration` | Discovery document |
| `/jwks` | JSON Web Key Set |
| `/authorize` | Authorization endpoint (GET/POST) |
| `/token` | Token endpoint |
| `/userinfo` | UserInfo endpoint |
| `/health` | Health check |

### Returned claims

`sub`, `email`, `name`, `preferred_username`

## Setup

### Configuration

Copy `config.example.toml` and adjust it:

```bash
cp config.example.toml config.toml
```

The config file path defaults to `/data/config.toml` and can be overridden with the `CONFIG_PATH` environment variable.

#### `[server]`

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `issuer_url` | yes | — | Public-facing URL of this service. Used as the OIDC issuer and to build endpoint URLs in the discovery document. Must match the URL clients use to reach the bridge (e.g. `https://sso.example.com`). |
| `listen_addr` | no | `0.0.0.0:8080` | Socket address the HTTP server binds to. |
| `key_path` | no | `/data/signing_key.pem` | Path to the RSA signing key. Generated automatically on first start. |
| `auth_code_ttl` | no | `60` | Authorization code lifetime in seconds. |
| `access_token_ttl` | no | `3600` | Access token lifetime in seconds. |
| `session_ttl` | no | `28800` | SSO session cookie lifetime in seconds (default: 8 hours). While active, returning users can authorize new clients without re-entering credentials. |

#### `[vereinsflieger]`

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `appkey` | yes | — | Your Vereinsflieger REST API application key. |
| `cid` | no | — | Club ID. Only needed if your users are members of multiple clubs and you want to restrict login to a specific one. |

#### `[[clients]]`

Register one or more OIDC/OAuth2 clients. Each entry needs:

| Key | Required | Description |
|-----|----------|-------------|
| `client_id` | yes | Unique identifier for the client application. |
| `client_secret` | yes | Shared secret for the token exchange. Use a long, random value. |
| `allowed_redirect_uris` | yes | List of allowed redirect URIs. The bridge will reject authorization requests with a `redirect_uri` not in this list. |

You can register multiple clients by repeating the `[[clients]]` section.

#### Example

```toml
[server]
issuer_url = "https://sso.example.com"

[vereinsflieger]
appkey = "your-vereinsflieger-appkey"

[[clients]]
client_id = "nextcloud"
client_secret = "change-me-to-a-random-secret"
allowed_redirect_uris = [
    "https://cloud.example.com/apps/oidc_login/oidc",
]
```

### Docker

```bash
docker build -t vf-oidc-bridge .
docker run -d \
  -p 8080:8080 \
  -v ./config.toml:/data/config.toml:ro \
  -v vf-oidc-data:/data \
  vf-oidc-bridge
```

The `/data` volume stores the RSA signing key (`signing_key.pem`). A key is generated automatically on first start.

#### Docker Compose

```yaml
services:
  vf-oidc-bridge:
    image: ghcr.io/your-org/vereinsflieger-oidc-bridge:latest
    # or build from source:
    # build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.toml:/data/config.toml:ro
      - vf-oidc-data:/data
    restart: unless-stopped

volumes:
  vf-oidc-data:
```

### Build from source

```bash
cargo build --release
CONFIG_PATH=config.toml ./target/release/vf-oidc-bridge
```

### Logging

Logging is controlled via the `RUST_LOG` environment variable (default: `info,tower_http=debug`).

## License

MIT
