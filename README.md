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

See [`config.example.toml`](config.example.toml) for all available options.

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

### Build from source

```bash
cargo build --release
CONFIG_PATH=config.toml ./target/release/vf-oidc-bridge
```

### Logging

Logging is controlled via the `RUST_LOG` environment variable (default: `info,tower_http=debug`).

## License

MIT
