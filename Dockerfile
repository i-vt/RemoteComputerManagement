# Dockerfile
#
# Single-stage build so cargo + rustup stay in the final image.
# The builder binary spawns `cargo build` at runtime to compile agents,
# which requires the Rust toolchain and source tree to be present.
#
# Image size: ~3-4 GB. This is expected for a C2 server that needs to
# cross-compile agents for multiple platforms.

FROM rust:latest

# ── System dependencies ────────────────────────────────────────────────
# - mingw-w64:       Windows cross-compilation (x86_64-pc-windows-gnu)
# - libssl-dev:      OpenSSL headers for the server binary
# - pkg-config:      Helps cargo find system libraries
# - cmake, clang:    Some crate build scripts need these
# - musl-tools:      Optional: musl libc for fully static Linux binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 \
        g++-mingw-w64-x86-64 \
        mingw-w64 \
        libssl-dev \
        pkg-config \
        cmake \
        clang \
        musl-tools \
        ca-certificates \
        curl \
        && rm -rf /var/lib/apt/lists/*

# ── Rust cross-compilation targets ────────────────────────────────────
# x86_64-unknown-linux-gnu  — native Linux (always available, explicit for clarity)
# x86_64-pc-windows-gnu     — Windows via mingw-w64
# macOS (x86_64-apple-darwin) requires osxcross and is not included here;
# attempting a macOS build from the UI will fail with a clear error message.
RUN rustup target add \
        x86_64-unknown-linux-gnu \
        x86_64-pc-windows-gnu

# Tell cargo to use the mingw linker for Windows targets
RUN mkdir -p /root/.cargo && cat >> /root/.cargo/config.toml << 'CARGOCONF'
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar = "x86_64-w64-mingw32-ar"
CARGOCONF

# ── Working directory ─────────────────────────────────────────────────
WORKDIR /app

# ── Dependency pre-caching ────────────────────────────────────────────
# Copy only the manifest files first. Docker caches this layer separately
# from the source code, so dependency downloads only re-run when
# Cargo.toml / Cargo.lock change, not on every source edit.
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./

# Create empty stub files for all [[bin]] targets so `cargo fetch`
# and the dependency build succeed without the real source.
RUN mkdir -p src/bin src/api/routes src/server src/agent/handlers \
             src/agent/injection/windows src/agent/injection \
             src/api \
    && echo 'fn main() {}' > src/main.rs \
    && for bin in server client builder client_dll client_service stager; do \
           echo 'fn main() {}' > src/bin/${bin}.rs; \
       done \
    && echo 'pub fn placeholder() {}' > src/lib.rs

# Fetch all dependencies (downloads crates, no compilation yet)
RUN cargo fetch

# ── Copy full source tree ─────────────────────────────────────────────
# Now copy the real source. The dependency layer above is already cached.
COPY src/ ./src/
COPY certs/ ./certs/
COPY panel/ ./panel/
COPY modules/ ./modules/
COPY extensions/ ./extensions/
COPY traffic_profiles/ ./traffic_profiles/
COPY fallback_profiles/ ./fallback_profiles/

# ── Build server binaries ─────────────────────────────────────────────
# Build the server and builder binaries for the native (Linux) target.
# The agent client binaries (client, client_dll, etc.) are NOT built here —
# they are compiled at runtime by the builder binary when an operator
# requests a new agent from the web UI.
RUN cargo build --release \
        --bin server \
        --bin builder \
        --target x86_64-unknown-linux-gnu \
    && cp target/x86_64-unknown-linux-gnu/release/server . \
    && cp target/x86_64-unknown-linux-gnu/release/builder .

# ── Runtime directories ───────────────────────────────────────────────
RUN mkdir -p logs downloads data dist

# ── Run as non-root ───────────────────────────────────────────────────
# uid 1000 matches what start_docker.sh chowns the mounted directories to.
RUN useradd -u 1000 -m -s /bin/bash rcm \
    && chown -R rcm:rcm /app \
    && chown -R rcm:rcm /root/.cargo \
    && chown -R rcm:rcm /usr/local/cargo \
    && chown -R rcm:rcm /usr/local/rustup

USER rcm

# ── Environment for runtime cargo builds ─────────────────────────────
# Make sure rustup/cargo are on PATH for the subprocess spawned by builder.
ENV PATH="/usr/local/cargo/bin:${PATH}"
ENV CARGO_HOME="/usr/local/cargo"
ENV RUSTUP_HOME="/usr/local/rustup"

# ── Healthcheck ───────────────────────────────────────────────────────
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/api/auth/me || exit 1

# ── Expose ports ──────────────────────────────────────────────────────
# 8080 — API + web panel
# 4443 — default TLS C2 listener
EXPOSE 8080 4443

CMD ["./server"]
