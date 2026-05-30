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

# Conditionally build pivot chain agents
COPY tests/docker/scripts/build-pivot-agents.sh /build/build-pivot-agents.sh
ARG BUILD_PIVOT_AGENTS=false
RUN if [ "$BUILD_PIVOT_AGENTS" = "true" ]; then \
        bash /build/build-pivot-agents.sh; \
    else \
        mkdir -p /build/pivot-agents && touch /build/pivot-agents/.empty; \
    fi

# ── Stage 4: Server runtime ────────────────────────────────────────────
FROM debian:bookworm-slim AS server

RUN apt-get update && apt-get install -y \
    ca-certificates openssl libsqlite3-0 curl python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/rcm
COPY --from=agents /build/target/release/server ./server
COPY --from=agents /build/certs/ ./certs/
COPY --from=agents /build/embedded/ ./embedded/
COPY --from=agents /build/extensions/ ./extensions/
COPY --from=agents /build/Cargo.lock.export ./Cargo.lock
# Pre-built agent binaries
COPY --from=agents /build/agent-tls ./agent-tls
COPY --from=agents /build/agent-http ./agent-http
COPY --from=agents /build/agent-tls.exe ./agent-tls.exe
COPY --from=agents /build/agent-http.exe ./agent-http.exe
# Build keys DB
COPY --from=agents /build/c2_audit.db ./c2_audit.db
COPY gen_certs.sh ./
COPY panel/ ./panel/
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
