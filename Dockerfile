FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
# Create dummy main to cache dependency builds
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

# Copy real source and build
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# --- Runtime image ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 app
RUN mkdir -p /data && chown app:app /data

COPY --from=builder /app/target/release/vf-oidc-bridge /usr/local/bin/vf-oidc-bridge

USER app
VOLUME /data
EXPOSE 8080

CMD ["vf-oidc-bridge"]
