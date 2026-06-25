#!/bin/bash
# tests/docker/scripts/build-pivot-agents.sh
#
# Builds all pivot agent binaries for the 4-chain pivot test.
# Called from the Dockerfile builder stage when BUILD_PIVOT_AGENTS=true.
#
# Chain 0 (Linux-only):  C2 → c0h1(L) → c0h2(L) → c0h3(L) → c0h4(L)
# Chain 1:               C2 → c1h1(L) → c1h2(W) → c1h3(W) → c1h4(L)
# Chain 2:               C2 → c2h1(W) → c2h2(W) → c2h3(L) → c2h4(L)
# Chain 3:               C2 → c3h1(W) → c3h2(L) → c3h3(W) → c3h4(L)
#
# Hop-1 agents in each chain connect directly to c2-server:4443 (TLS)
# and reuse the existing agent-tls / agent-tls.exe binaries.
# Hop-2/3/4 agents connect to their parent's pivot listener (tcp_plain).

set -euo pipefail

BUILDER="./target/release/builder"
OUT="/build/pivot-agents"
mkdir -p "$OUT"

build_agent() {
    local name="$1" host="$2" port="$3" platform="$4"
    local ext=""
    [ "$platform" = "windows" ] && ext=".exe"

    echo "[pivot] Building ${name} → ${host}:${port} (${platform})"
    rm -f dist/exe_*
    "$BUILDER" \
        --host "$host" --port "$port" \
        --transport tcp-plain \
        --platform "$platform" \
        --sleep 2 --jitter-min 0 --jitter-max 0 --debug \
        2>&1 | tail -1

    if [ "$platform" = "windows" ]; then
        cp dist/exe_windows_*.exe "${OUT}/${name}.exe"
    else
        cp dist/exe_linux_* "${OUT}/${name}"
    fi
    echo "[+] ${name} built"
}

echo "=== Building pivot agent binaries ==="

# ── Chain 0: Linux-only (C2 → L → L → L → L) ──────────────────────────
# hop1 reuses agent-tls (direct to C2)
build_agent "c0h2" "c0-hop1" "5001" "linux"
build_agent "c0h3" "c0-hop2" "5002" "linux"
build_agent "c0h4" "c0-hop3" "5003" "linux"

# ── Chain 1: C2 → L → W → W → L ───────────────────────────────────────
# hop1 reuses agent-tls (direct to C2)
build_agent "c1h2" "c1-hop1" "5101" "windows"
build_agent "c1h3" "c1-hop2" "5102" "windows"
build_agent "c1h4" "c1-hop3" "5103" "linux"

# ── Chain 2: C2 → W → W → L → L ───────────────────────────────────────
# hop1 reuses agent-tls.exe (direct to C2)
build_agent "c2h2" "c2-hop1" "5201" "windows"
build_agent "c2h3" "c2-hop2" "5202" "linux"
build_agent "c2h4" "c2-hop3" "5203" "linux"

# ── Chain 3: C2 → W → L → W → L ───────────────────────────────────────
# hop1 reuses agent-tls.exe (direct to C2)
build_agent "c3h2" "c3-hop1" "5301" "linux"
build_agent "c3h3" "c3-hop2" "5302" "windows"
build_agent "c3h4" "c3-hop3" "5303" "linux"

echo "=== All pivot agents built ==="
ls -la "$OUT"/
