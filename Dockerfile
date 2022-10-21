FROM rust:1.62.0-slim AS builder

# Install dependencies
RUN set -ex && apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    protobuf-compiler \
    libssl-dev

# Build application in /usr/src folder
RUN cargo new /usr/src/rust_playground
WORKDIR /usr/src/rust_playground
COPY Cargo.toml Cargo.lock ./

# Update crates.io index
RUN --mount=type=cache,target=/root/.cargo \
    cargo update

# Build dependencies into cache
RUN --mount=type=cache,target=/root/.cargo \
    --mount=type=cache,sharing=private,target=/usr/src/rust_playground/target \
    cargo build --profile release-lto

# Build App
COPY . .
RUN --mount=type=cache,target=/root/.cargo \
    --mount=type=cache,sharing=private,target=/usr/src/rust_playground/target \
    set -ex ;\
    touch src/main.rs ;\
    cargo build --profile release-lto --bins ;\
    strip target/release-lto/ssh-honeypot

# Copy app from cache diretory to container image
RUN --mount=type=cache,sharing=private,target=/usr/src/rust_playground/target \
    cp target/release-lto/ssh-honeypot /usr/local/bin/ssh-honeypot

# Bundle App into a minimal image
FROM gcr.io/distroless/cc AS runtime
COPY --from=builder /usr/local/bin/ssh-honeypot /usr/local/bin/ssh-honeypot

USER 1000

ENV RUST_LOG=info
WORKDIR /

CMD ["/usr/local/bin/ssh-honeypot"]
