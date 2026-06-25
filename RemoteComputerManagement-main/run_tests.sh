#!/usr/bin/env bash
# run_tests.sh — Run RCM tests inside Docker.
#
# Two test suites:
#
#   Unit tests   — cargo test --lib (all Rust #[test] items, no server needed)
#   Integration  — 12 bash scripts (test_01–test_12) against a live stack
#
# Usage:
#   ./run_tests.sh                  # unit tests only  (fast, ~30s)
#   ./run_tests.sh --integration    # integration tests, standard suite
#   ./run_tests.sh --pivot          # integration + pivot chain (test_09, Linux-only chain)
#   ./run_tests.sh --windows        # integration + Windows overlay (test_08; needs Windows Docker host)
#   ./run_tests.sh --all            # unit + integration
#   ./run_tests.sh --module <name>  # one unit-test module (debugging)
#   ./run_tests.sh --no-cache       # force full Docker rebuild
#   ./run_tests.sh --help
#
# Exit codes:
#   0  all tests passed
#   1  one or more tests failed
#   2  prerequisites not met or build failed

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────────

UNIT_COMPOSE="tests/docker/docker-compose.unit.yml"
INT_COMPOSE="tests/docker/docker-compose.yml"
PIVOT_OVERLAY="tests/docker/docker-compose.pivot.yml"
WINDOWS_OVERLAY="tests/docker/docker-compose.windows.yml"
UNIT_MODULES=(topology transport database hibernation interface extension)

BUILD_ARGS=()
TARGET_MODULE=""
RUN_UNIT=1
RUN_INTEGRATION=0
PIVOT_MODE=0
WINDOWS_MODE=0
RUN_PIVOT_PHASE=0
SHOW_HELP=0

# ── Colours ────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${CYAN}[•]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()    { echo -e "${RED}[✗]${RESET} $*"; }
header()  { echo -e "\n${BOLD}$*${RESET}"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run RCM tests inside Docker.

Modes (combine freely):
  (default)        Unit tests only — no server needed (~30s)
  --integration    All 12 integration tests (standard suite, ~5 min)
  --pivot          Integration + pivot chain agents (test_09, Linux-only chain ~10 min)
  --windows        Integration + Windows overlay (test_08; agent runs on Windows
                   Docker host only; on Linux the test skips gracefully)
  --all            Unit + standard integration (with windows overlay) + pivot phase

Unit test options:
  --module <name>  Run one module only: ${UNIT_MODULES[*]}

Shared options:
  --no-cache       Force a full Docker rebuild
  --help           Show this message

Notes:
  --pivot and --windows imply --integration.
  --pivot builds pivot chain agents (BUILD_PIVOT_AGENTS=true) and runs
    the Linux-only 4-hop chain (C2 → L → L → L → L).
  --windows requires Docker Desktop in Windows containers mode to run the
    agent; on Linux it enables WINDOWS_AGENT=1 so test_08 runs its checks
    and skips informatively when no Windows session connects.

Examples:
  ./run_tests.sh                          # unit tests only
  ./run_tests.sh --integration            # all 12 integration tests
  ./run_tests.sh --pivot                  # integration + pivot chains
  ./run_tests.sh --all                    # unit + integration
  ./run_tests.sh --all --pivot --windows  # everything
  ./run_tests.sh --no-cache --all         # rebuild then run everything
EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --integration)
            RUN_UNIT=0; RUN_INTEGRATION=1; shift ;;
        --pivot)
            RUN_UNIT=0; RUN_INTEGRATION=1; PIVOT_MODE=1; shift ;;
        --windows)
            RUN_UNIT=0; RUN_INTEGRATION=1; WINDOWS_MODE=1; shift ;;
        --all)
            RUN_UNIT=1; RUN_INTEGRATION=1; WINDOWS_MODE=1; RUN_PIVOT_PHASE=1; shift ;;
        --module)
            [[ -z "${2:-}" ]] && { fail "--module requires a name"; exit 2; }
            TARGET_MODULE="$2"; shift 2 ;;
        --no-cache)
            BUILD_ARGS+=(--no-cache); shift ;;
        --help|-h)
            SHOW_HELP=1; shift ;;
        *)
            fail "Unknown option: $1"; usage; exit 2 ;;
    esac
done

[[ "$SHOW_HELP" -eq 1 ]] && { usage; exit 0; }

if [[ -n "$TARGET_MODULE" ]]; then
    valid=0
    for m in "${UNIT_MODULES[@]}"; do
        [[ "$m" == "$TARGET_MODULE" ]] && valid=1 && break
    done
    [[ $valid -eq 0 ]] && { fail "Unknown module '$TARGET_MODULE'. Valid: ${UNIT_MODULES[*]}"; exit 2; }
fi

# ── Prerequisites ──────────────────────────────────────────────────────────────

header "═══ RCM Tests ═══"

check_cmd() { command -v "$1" &>/dev/null || { fail "$1 not found."; exit 2; }; }
check_cmd docker

if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    fail "Neither 'docker compose' nor 'docker-compose' found."; exit 2
fi

[[ ! -f "gen_certs.sh" ]] && { fail "Run from the project root (gen_certs.sh not found)."; exit 2; }
[[ $RUN_UNIT -eq 1 && ! -f "$UNIT_COMPOSE" ]] && { fail "Not found: $UNIT_COMPOSE"; exit 2; }
[[ $RUN_INTEGRATION -eq 1 && ! -f "$INT_COMPOSE" ]] && { fail "Not found: $INT_COMPOSE"; exit 2; }
[[ $PIVOT_MODE -eq 1 && ! -f "$PIVOT_OVERLAY" ]] && { fail "Not found: $PIVOT_OVERLAY"; exit 2; }
[[ $WINDOWS_MODE -eq 1 && ! -f "$WINDOWS_OVERLAY" ]] && { fail "Not found: $WINDOWS_OVERLAY"; exit 2; }

info "Docker:  $(docker --version)"
info "Compose: $($COMPOSE version 2>/dev/null | head -1)"

# ── Counters ───────────────────────────────────────────────────────────────────

UNIT_EXIT=0
INT_EXIT=0
PIVOT_EXIT=0

# ── Unit tests ─────────────────────────────────────────────────────────────────

run_unit_tests() {
    local total=$(( RUN_UNIT + (RUN_INTEGRATION > 0 ? 1 : 0) ))
    header "Phase 1/${total} — Unit tests (cargo test --lib)"
    info "Compose: $UNIT_COMPOSE"

    local build_svc="${TARGET_MODULE:+unit-${TARGET_MODULE}}"
    build_svc="${build_svc:-unit-all}"

    local build_start; build_start=$(date +%s)
    $COMPOSE -f "$UNIT_COMPOSE" build "${BUILD_ARGS[@]}" "$build_svc" \
        || { fail "Unit test image build failed."; UNIT_EXIT=2; return; }
    # All unit services share the same Dockerfile — tag the built image so
    # unit-dga and unit-fallback can find it without a separate build.
    docker tag rcm-unit-tests-unit-all:latest rcm-unit-tests-unit-dga:latest 2>/dev/null || true
    docker tag rcm-unit-tests-unit-all:latest rcm-unit-tests-unit-fallback:latest 2>/dev/null || true
    info "Build: $(($(date +%s) - build_start))s"
    echo ""

    local run_start; run_start=$(date +%s)
    if [[ -n "$TARGET_MODULE" ]]; then
        $COMPOSE -f "$UNIT_COMPOSE" run --rm "unit-${TARGET_MODULE}" || UNIT_EXIT=$?
    else
        $COMPOSE -f "$UNIT_COMPOSE" run --rm unit-all || UNIT_EXIT=$?
    fi
    info "Duration: $(($(date +%s) - run_start))s"
    $COMPOSE -f "$UNIT_COMPOSE" rm -f --stop 2>/dev/null || true

    [[ $UNIT_EXIT -eq 0 ]] && success "Unit tests passed." \
        || { fail "Unit tests FAILED (exit $UNIT_EXIT)."; warn "Debug: ./run_tests.sh --module <name>"; }
}

# ── Integration tests ──────────────────────────────────────────────────────────

run_integration_tests() {
    local phase=$(( RUN_UNIT + 1 ))
    local total=$(( RUN_UNIT + 1 ))
    header "Phase ${phase}/${total} — Integration tests (test_01–test_12)"
    info "Compose: $INT_COMPOSE"
    [[ $PIVOT_MODE -eq 1 ]]   && info "Overlay: $PIVOT_OVERLAY (pivot chain, --profile pivot)"
    [[ $WINDOWS_MODE -eq 1 ]] && info "Overlay: $WINDOWS_OVERLAY (WINDOWS_AGENT=1)"
    warn "Building full server binary — allow ~5–10 min."
    echo ""

    export TEST_SUITE="${TEST_SUITE:-full}"
    [[ $PIVOT_MODE -eq 1 ]] && TEST_SUITE="pivot"
    info "Suite: $TEST_SUITE"
    echo ""

    local int_start; int_start=$(date +%s)

    # ── Pre-build images using docker build (bypasses compose bake path bugs) ──
    # Build context is . (project root). Dockerfile is copied to the context root
    # so -f uses a bare filename with no directory prefix — unambiguous in all
    # builder versions. The copy is cleaned up via trap.

    (
        local_exit=0

        local no_cache=""
        for a in ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}; do
            [[ "$a" == "--no-cache" ]] && no_cache="--no-cache"
        done

        # Diagnose the Dockerfile before building
        info "Dockerfile stages in tests/docker/Dockerfile:"
        grep "^FROM" tests/docker/Dockerfile || {
            fail "tests/docker/Dockerfile not found or has no FROM lines"
            exit 2
        }
        echo ""

        local tmp_df=""; tmp_df="$(pwd)/tests/docker/Dockerfile"

        # Server image — with pivot agents if requested
        info "Building server image..."
        local pivot_arg=""
        [[ $PIVOT_MODE -eq 1 ]] && pivot_arg="--build-arg BUILD_PIVOT_AGENTS=true"

        docker build ${no_cache:+"$no_cache"} ${pivot_arg} \
            -f "$tmp_df" --target server \
            -t docker-c2-server . || { local_exit=$?; exit "$local_exit"; }

        # Agent image
        info "Building agent image..."
        docker build ${no_cache:+"$no_cache"} \
            -f "$tmp_df" --target agent \
            -t docker-agent-1 -t docker-agent-2 -t docker-agent-hibernation . \
            || { local_exit=$?; exit "$local_exit"; }

        # ── Run compose from tests/docker/ with appropriate overlays ──────────
        cd tests/docker || exit 2

        # Build compose file list and profiles
        local compose_files="-f docker-compose.yml"
        local profiles=""
        [[ $PIVOT_MODE -eq 1 ]]   && compose_files+=" -f docker-compose.pivot.yml" && profiles="--profile pivot"
        [[ $WINDOWS_MODE -eq 1 ]] && compose_files+=" -f docker-compose.windows.yml"
        # Note: --profile windows is intentionally omitted on Linux; the agent-windows
        # container requires Windows Docker host. WINDOWS_AGENT=1 is set by the overlay
        # environment, so test_08 runs and skips informatively if no session connects.

        # shellcheck disable=SC2086
        $COMPOSE $compose_files up --no-build $profiles \
            --abort-on-container-exit \
            --exit-code-from test-runner || local_exit=$?

        # shellcheck disable=SC2086
        $COMPOSE $compose_files down --remove-orphans 2>/dev/null || true
        exit "$local_exit"
    ) || INT_EXIT=$?

    info "Duration: $(($(date +%s) - int_start))s"

    if [[ $INT_EXIT -eq 0 ]]; then
        success "Integration tests passed."
    else
        fail "Integration tests FAILED (exit $INT_EXIT)."
        if [[ $PIVOT_MODE -eq 0 && $WINDOWS_MODE -eq 0 ]]; then
            warn "Isolate failures: TEST_SUITE=smoke ./run_tests.sh --integration"
        fi
    fi
}

# ── Pivot phase (separate stack re-up) ─────────────────────────────────────
run_pivot_phase() {
    header "Phase extra — Pivot chains (test_09, re-upping containers)"
    info "Tearing down standard stack, rebuilding with BUILD_PIVOT_AGENTS=true..."
    warn "First run ~10 min; subsequent runs use cache."
    echo ""

    local int_start; int_start=$(date +%s)
    (
        local_exit=0

        local no_cache=""
        for a in ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}; do
            [[ "$a" == "--no-cache" ]] && no_cache="--no-cache"
        done

        local tmp_df=""; tmp_df="$(pwd)/tests/docker/Dockerfile"

        info "Building server image with pivot agents..."
        docker build ${no_cache:+"$no_cache"} --build-arg BUILD_PIVOT_AGENTS=true \
            -f "$tmp_df" --target server -t docker-c2-server . \
            || { local_exit=$?; exit "$local_exit"; }

        docker build ${no_cache:+"$no_cache"} \
            -f "$tmp_df" --target agent \
            -t docker-agent-1 -t docker-agent-2 -t docker-agent-hibernation . \
            || { local_exit=$?; exit "$local_exit"; }

        cd tests/docker || exit 2

        $COMPOSE -f docker-compose.yml -f docker-compose.pivot.yml \
            --profile pivot up --no-build \
            --abort-on-container-exit \
            --exit-code-from test-runner || local_exit=$?

        $COMPOSE -f docker-compose.yml -f docker-compose.pivot.yml \
            down --remove-orphans 2>/dev/null || true
        exit "$local_exit"
    ) || PIVOT_EXIT=$?

    info "Duration: $(($(date +%s) - int_start))s"
    [[ $PIVOT_EXIT -eq 0 ]] && success "Pivot phase passed." \
        || fail "Pivot phase FAILED (exit $PIVOT_EXIT)."
}

# ── Run ────────────────────────────────────────────────────────────────────────

[[ $RUN_UNIT -eq 1 ]]        && run_unit_tests
[[ $RUN_INTEGRATION -eq 1 ]] && run_integration_tests
[[ $RUN_PIVOT_PHASE -eq 1 || $PIVOT_MODE -eq 1 ]] && run_pivot_phase

# ── Summary ────────────────────────────────────────────────────────────────────

OVERALL=$(( UNIT_EXIT | INT_EXIT | PIVOT_EXIT ))

header "═══ Results ═══"
echo ""
[[ $RUN_UNIT -eq 1 ]] && {
    [[ $UNIT_EXIT -eq 0 ]] && success "Unit        passed" || fail "Unit        FAILED"
}
[[ $RUN_INTEGRATION -eq 1 ]] && {
    [[ $INT_EXIT -eq 0 ]] && success "Integration  passed" || fail "Integration  FAILED"
}
[[ $RUN_PIVOT_PHASE -eq 1 || $PIVOT_MODE -eq 1 ]] && {
    [[ $PIVOT_EXIT -eq 0 ]] && success "Pivot        passed" || fail "Pivot        FAILED"
}
echo ""
[[ $OVERALL -eq 0 ]] && success "All tests passed." || fail "Tests failed."

exit "$OVERALL"
