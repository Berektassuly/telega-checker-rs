# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1: Build the Rust binary
# ═══════════════════════════════════════════════════════════════════════════════
FROM rust:1.92-slim-bookworm AS builder

# Install build-time dependencies (native-tls for reqwest)
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Dependency caching layer ─────────────────────────────────────────────────
# Copy manifests first so Docker can cache the dependency build step.
# Only re-runs when Cargo.toml or Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# ── Build the actual binary ──────────────────────────────────────────────────
COPY src/ src/
# Touch main.rs to invalidate the dummy binary but keep compiled deps
RUN touch src/main.rs && \
    cargo build --release

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2: Minimal runtime image
# ═══════════════════════════════════════════════════════════════════════════════
FROM debian:bookworm-slim

# Install runtime dependencies only (TLS certs + OpenSSL shared lib)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid appuser --shell /bin/false appuser

# Create data directory for SQLite volume mount
RUN mkdir -p /app/data && chown appuser:appuser /app/data

WORKDIR /app

# Copy compiled binary from builder
COPY --from=builder /build/target/release/telega-checker-rs ./

# Drop to non-root
USER appuser

# Expose the HTTP API port (internal Docker network only; Nginx proxies to this)
EXPOSE 8080

CMD ["./telega-checker-rs"]
