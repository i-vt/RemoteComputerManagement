# tests/docker/Dockerfile
# Multi-stage build for RCM integration testing.
#
# Stages:
#   builder     — compiles server, builder, and client binaries
#   unit-test   — runs cargo test; FAILS THE BUILD on test failure
#   agents      — builds test agents from the compiled builder
#   server      — runtime image for the team server
#   agent       — runtime image for a test agent
#
# Usage:
#   docker compose -f tests/docker/docker-compose.yml up --build

# ── Stage 1: Compile everything ─────────────────────────────────────────
# Pinned Rust version. Bump this when dependencies raise their MSRV.
# The committed Cargo.lock ensures transitive deps don't drift.
FROM rust:bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev openssl cmake \
    gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./
COPY gen_certs.sh ./
COPY src/ src/
COPY embedded/ embedded/
COPY dga_templates/ dga_templates/
COPY extensions/ extensions/

# Generate TLS certificates (needed for include_bytes! at compile time)
RUN bash gen_certs.sh

# Add Windows cross-compilation target
RUN rustup target add x86_64-pc-windows-gnu

# Pin dependency versions. If Cargo.lock was COPY'd above, this is a
# no-op. If not (first build / lock not committed), it creates one.
RUN cargo generate-lockfile

# Build all binary targets in release mode
RUN cargo build --release --bin server --bin builder --bin client 2>&1

# ── Stage 2: Unit test gate ─────────────────────────────────────────────
# Runs unit + integration tests. NO || true — a test failure stops the
# entire Docker build. This is intentional: broken tests should never
# produce a "green" integration run.
FROM builder AS unit-test
RUN cargo test --lib --tests 2>&1

# ── Stage 3: Build test agents ──────────────────────────────────────────
# Depends on unit-test so agents are only built after tests pass.
FROM unit-test AS agents

# "c2-server" is the deterministic Docker Compose network hostname.
RUN mkdir -p dist && \
    ./target/release/builder --host c2-server --port 4443 --transport tls \
        --platform linux --sleep 2 --jitter-min 0 --jitter-max 0 --debug && \
    cp dist/exe_linux_* /build/agent-tls && \
    rm -f dist/exe_linux_* && \
    echo "[+] TLS agent built"

RUN ./target/release/builder --host c2-server --port 4480 --transport http \
        --platform linux --sleep 2 --jitter-min 0 --jitter-max 0 --debug && \
    cp dist/exe_linux_* /build/agent-http && \
    echo "[+] HTTP agent built"

# Cross-compile Windows agents (mingw-w64)
RUN rm -f dist/exe_windows_* && \
    ./target/release/builder --host c2-server --port 4443 --transport tls \
        --platform windows --sleep 2 --jitter-min 0 --jitter-max 0 --debug && \
    cp dist/exe_windows_*.exe /build/agent-tls.exe && \
    rm -f dist/exe_windows_* && \
    echo "[+] Windows TLS agent built"

RUN ./target/release/builder --host c2-server --port 4480 --transport http \
        --platform windows --sleep 2 --jitter-min 0 --jitter-max 0 --debug && \
    cp dist/exe_windows_*.exe /build/agent-http.exe && \
    echo "[+] Windows HTTP agent built"

# Export the lockfile so it can be committed to the repo
RUN cp Cargo.lock /build/Cargo.lock.export

# Build hibernation (dweller) agent — TLS transport, short sleep so it
# stays visible in /api/hosts throughout the test suite run.
RUN rm -f dist/exe_linux_* && \
    ./target/release/builder --host c2-server --port 4443 --transport tls \
        --platform linux --sleep 5 --jitter-min 0 --jitter-max 2 --debug \
        --hibernation --batch-size 3 && \
    cp dist/exe_linux_* /build/agent-hibernation

# Conditionally build pivot chain agents
COPY tests/docker/scripts/build-pivot-agents.sh /build/build-pivot-agents.sh
ARG BUILD_PIVOT_AGENTS=false
RUN if [ "$BUILD_PIVOT_AGENTS" = "true" ]; then \
        bash /build/build-pivot-agents.sh; \
    else \
        mkdir -p /build/pivot-agents && touch /build/pivot-agents/.empty; \
    fi

# ── Stage 4: Server runtime ────────────────────────────────────────────
# Inherits debian:bookworm-slim for a lean base, but augments it with the
# Rust toolchain and project source tree so the builder binary can compile
# agents on demand in response to POST /api/builder/build requests.
#
# Without the toolchain and source, the builder binary spawns successfully
# but cargo build immediately fails (no compiler, no Cargo.toml), causing
# every API-triggered build to land in status=failed.
FROM debian:bookworm-slim AS server

# Runtime deps + build-time system libraries required by the agent crate
# (openssl-sys, ring) and for Windows cross-compilation (mingw-w64).
# build-essential provides the native C linker (cc/gcc) that rustc needs
# to link the final binary — debian:bookworm-slim does not include it.
RUN apt-get update && apt-get install -y \
    ca-certificates openssl libsqlite3-0 curl python3 \
    build-essential pkg-config libssl-dev \
    gcc-mingw-w64-x86-64 \
    libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev \
    libxcb-shape0-dev libxcb-xfixes0-dev \
    libx11-dev libxrandr-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Rust toolchain ──────────────────────────────────────────────────────
# Copy cargo/rustup from the build stage so `cargo build` works at runtime.
# The toolchain is at the standard paths used by the rust:bookworm image.
COPY --from=agents /usr/local/cargo /usr/local/cargo
COPY --from=agents /usr/local/rustup /usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}"
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup

WORKDIR /opt/rcm

# ── Project source tree ─────────────────────────────────────────────────
# The builder binary's find_project_root() checks CWD (/opt/rcm) and the
# directory adjacent to the binary (/opt/rcm) for Cargo.toml. Both resolve
# to /opt/rcm, so the source must live here.
COPY --from=agents /build/Cargo.toml ./
COPY --from=agents /build/Cargo.lock.export ./Cargo.lock
COPY --from=agents /build/build.rs ./
COPY --from=agents /build/src/ ./src/
COPY --from=agents /build/embedded/ ./embedded/
COPY --from=agents /build/extensions/ ./extensions/
COPY --from=agents /build/dga_templates/ ./dga_templates/

# ── Pre-compiled dependency cache ───────────────────────────────────────
# The build stage compiled with RUSTFLAGS containing
# --remap-path-prefix /build=/src, but the runtime runs from /opt/rcm.
# Copying that target/ would cause cargo to invalidate every cached
# artifact (RUSTFLAGS fingerprint mismatch) and then attempt a full
# recompile — slower than starting clean and blowing BUILD_TIMEOUT.
# Instead, seed the registry cache only so crates don't re-download.
COPY --from=agents /usr/local/cargo/registry /usr/local/cargo/registry

# Certs are copied rather than regenerated here because the pre-built
# agent binaries (agent-tls, agent-http, agent-hibernation) compiled in
# the agents stage embed the CA cert via include_bytes! at compile time.
# Generating new certs here would produce a server cert signed by a
# different CA than what the agents trust, breaking every TLS handshake.
#
# In production, mount /opt/rcm/certs/ as a Docker volume and generate
# fresh certs at first launch via gen_certs.sh in the entrypoint. That
# way each deployment has unique material and nothing sensitive lives in
# the image layer.
COPY --from=agents /build/certs/ ./certs/

# ── Pre-warm dependency compilation ─────────────────────────────────────
# Build the client binary once here, with the exact RUSTFLAGS the builder
# binary will use at runtime (project_root=/opt/rcm). This populates
# target/ with correctly-fingerprinted artifacts for all dependency crates.
# API-triggered builds then only recompile the project's own crates
# (obfuscated config, litcrypt key churn) — roughly 60s vs 15+ minutes
# for a cold build — keeping them within BUILD_TIMEOUT=180.
RUN RUSTFLAGS="--remap-path-prefix /opt/rcm=/src --remap-path-prefix /usr/local/cargo=/cargo" \
    cargo build --release --target x86_64-unknown-linux-gnu --bin client \
    && echo "[prewarm] dependency cache ready"

# ── Server runtime artifacts ────────────────────────────────────────────
COPY --from=agents /build/target/release/server ./server
COPY --from=agents /build/target/release/builder ./builder
COPY --from=agents /build/c2_audit.db ./c2_audit.db

# ── Pre-built agent binaries ────────────────────────────────────────────
COPY --from=agents /build/agent-tls ./agent-tls
COPY --from=agents /build/agent-http ./agent-http
COPY --from=agents /build/agent-hibernation ./agent-hibernation
COPY --from=agents /build/agent-tls.exe ./agent-tls.exe
COPY --from=agents /build/agent-http.exe ./agent-http.exe

COPY gen_certs.sh ./
COPY panel/ ./panel/
COPY modules/ ./modules/
COPY --from=agents /build/pivot-agents/ ./pivot-agents/

RUN mkdir -p modules dist downloads

COPY tests/docker/scripts/server-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 4443 8080
ENTRYPOINT ["/entrypoint.sh"]

# ── Stage 5: Agent runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim AS agent

RUN apt-get update && apt-get install -y \
    ca-certificates curl \
    libxcb1 libxcb-shm0 libxcb-randr0 libxcb-shape0 libxcb-xfixes0 \
    libx11-6 libxrandr2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agent

COPY tests/docker/scripts/agent-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
