#!/usr/bin/env bash
# run_tests.sh - Run RCM tests inside Docker.
#
# Two test suites:
#
#   Unit tests   - cargo test (all Rust #[test] items, no server needed)
#   Integration  - bash scripts (test_01-test_19) against a live stack
#   String audit - OPSEC denylist scan of release agent binaries
#                  (tools/string_audit.sh; runs as a build-failing stage in
#                  the integration image build, plus a host-mode scan of
#                  target/x86_64-pc-windows-gnu/release when present)
#
# Usage:
#   ./run_tests.sh                  # unit tests only  (fast, ~30s)
#   ./run_tests.sh --integration    # integration tests, standard suite
#   ./run_tests.sh --pivot          # integration + pivot chain (test_09, Linux-only chain)
#   ./run_tests.sh --windows        # integration + Windows overlay (test_08; needs Windows Docker host)
#   ./run_tests.sh --all            # unit + integration
#   ./run_tests.sh --module <name>  # one unit-test module (debugging)
#   ./run_tests.sh --no-cache       # force full Docker rebuild
#   ./run_tests.sh --clean          # docker system prune -a --volumes --force first
#   ./run_tests.sh --summary        # terse console output (AI-agent friendly)
#   ./run_tests.sh --json           # last stdout line is ONLY the RESULTS_JSON
#   ./run_tests.sh --help
#
# The final output line is always a machine-readable RESULTS_JSON {...} line.
# Every run also persists that JSON (plus timestamp_utc and a dist/ artifacts
# list) to tests/results/last.json and a timestamped archive under
# tests/results/result_<UTC-yyyymmdd-HHMMSS>.json.
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
UNIT_MODULES=(topology transport database hibernation interface extension dga fallback shellcode)

BUILD_ARGS=()
TARGET_MODULE=""
RUN_UNIT=1
RUN_INTEGRATION=0
PIVOT_MODE=0
WINDOWS_MODE=0
RUN_PIVOT_PHASE=0
SHOW_HELP=0
CLEAN=0
SUMMARY=0
JSON_ONLY=0

# Run start marker - used to detect build artifacts produced by this run.
RUN_START_EPOCH=$(date +%s)

# Captured phase output (used for RESULTS_JSON parsing and --summary filtering)
UNIT_LOG=""
INT_LOG=""
PIVOT_LOG=""

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
  (default)        Unit tests only - no server needed (~30s)
  --integration    All integration tests (standard suite, ~5 min)
  --pivot          Integration + pivot chain agents (test_09, Linux-only chain ~10 min)
  --windows        Integration + Windows overlay (test_08; agent runs on Windows
                   Docker host only; on Linux the test skips gracefully)
  --all            Unit + standard integration (with windows overlay) + pivot phase

Unit test options:
  --module <name>  Run one module only: ${UNIT_MODULES[*]}

Shared options:
  --no-cache       Force a full Docker rebuild
  --clean          Clean slate FIRST: docker system prune -a --volumes --force
                   (non-interactive) runs before any build; alias: --prune.
                   Running containers (e.g. a live rcm-server stack) are NOT
                   stopped; in-use images/volumes survive the prune.
  --summary        Terse, AI-agent-friendly console output: only phase headers,
                   failing test names + their ✗ lines, the TOTAL line and the
                   Results block are printed. Full output is written to
                   \${RCM_TEST_LOG:-/tmp/rcm_last_test.log} and the path is printed.
  --json           Machine-readable mode: the LAST line of stdout is ONLY the
                   RESULTS_JSON line (nothing after it), so
                   RESULT=\$($0 --json | tail -1) parses cleanly. The
                   "Results saved to ..." notice is suppressed from stdout
                   (still written to the log file in --summary mode).
  --help           Show this message

Notes:
  The last output line is always RESULTS_JSON {...} - machine-readable
    per-phase pass/fail/skip status plus parsed test counts.
  Every run persists results to tests/results/last.json and a timestamped
    archive tests/results/result_<UTC-yyyymmdd-HHMMSS>.json (see
    tests/results/README.md). The JSON includes timestamp_utc and an
    artifacts array (dist/ files produced by this run, name + size).
  --pivot and --windows imply --integration.
  --pivot builds pivot chain agents (BUILD_PIVOT_AGENTS=true) and runs
    the Linux-only 4-hop chain (C2 → L → L → L → L).
  --windows requires Docker Desktop in Windows containers mode to run the
    agent; on Linux it enables WINDOWS_AGENT=1 so test_08 runs its checks
    and skips informatively when no Windows session connects.

Examples:
  ./run_tests.sh                          # unit tests only
  ./run_tests.sh --integration            # all 19 integration tests
  ./run_tests.sh --pivot                  # integration + pivot chains
  ./run_tests.sh --all                    # unit + integration
  ./run_tests.sh --all --pivot --windows  # everything
  ./run_tests.sh --no-cache --all         # rebuild then run everything
  ./run_tests.sh --clean --all --summary  # prune first, run everything, terse output
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
        --clean|--prune)
            CLEAN=1; shift ;;
        --summary)
            SUMMARY=1; shift ;;
        --json)
            JSON_ONLY=1; shift ;;
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

# ── Optional clean slate (runs BEFORE any build) ───────────────────────────────

if [[ $CLEAN -eq 1 ]]; then
    header "Clean slate - docker system prune -a --volumes --force"
    warn "Pruning all unused images, stopped containers, networks and volumes."
    warn "Running containers (e.g. a live rcm-server stack) are NOT stopped;"
    warn "their images and in-use volumes (cargo-registry/cargo-target/cargo-git)"
    warn "survive the prune. Reclaimed space is reported by docker below."
    echo ""
    docker system prune -a --volumes --force
    echo ""
    success "Clean complete."
    echo ""
fi

# ── Counters ───────────────────────────────────────────────────────────────────

UNIT_EXIT=0
INT_EXIT=0
PIVOT_EXIT=0
AUDIT_EXIT=0
AUDIT_RAN=0

# ── Unit tests ─────────────────────────────────────────────────────────────────

run_unit_tests() {
    local total=$(( RUN_UNIT + (RUN_INTEGRATION > 0 ? 1 : 0) ))
    header "Phase 1/${total} - Unit tests (cargo test)"
    info "Compose: $UNIT_COMPOSE"

    local build_svc="${TARGET_MODULE:+unit-${TARGET_MODULE}}"
    build_svc="${build_svc:-unit-all}"

    local build_start; build_start=$(date +%s)
    $COMPOSE -f "$UNIT_COMPOSE" build "${BUILD_ARGS[@]}" "$build_svc" \
        || { fail "Unit test image build failed."; UNIT_EXIT=2; return; }
    # All unit services share the same Dockerfile - tag the built image so
    # unit-dga and unit-fallback can find it without a separate build.
    docker tag rcm-unit-tests-unit-all:latest rcm-unit-tests-unit-dga:latest 2>/dev/null || true
    docker tag rcm-unit-tests-unit-all:latest rcm-unit-tests-unit-fallback:latest 2>/dev/null || true
    docker tag rcm-unit-tests-unit-all:latest rcm-unit-tests-unit-shellcode:latest 2>/dev/null || true
    info "Build: $(($(date +%s) - build_start))s"
    echo ""

    local run_start; run_start=$(date +%s)
    UNIT_LOG="$(mktemp /tmp/rcm_unit_out.XXXXXX.log)"
    if [[ -n "$TARGET_MODULE" ]]; then
        $COMPOSE -f "$UNIT_COMPOSE" run --rm "unit-${TARGET_MODULE}" 2>&1 | tee "$UNIT_LOG" || UNIT_EXIT=$?
    else
        $COMPOSE -f "$UNIT_COMPOSE" run --rm unit-all 2>&1 | tee "$UNIT_LOG" || UNIT_EXIT=$?
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
    header "Phase ${phase}/${total} - Integration tests (test_01-test_19)"
    info "Compose: $INT_COMPOSE"
    [[ $PIVOT_MODE -eq 1 ]]   && info "Overlay: $PIVOT_OVERLAY (pivot chain, --profile pivot)"
    [[ $WINDOWS_MODE -eq 1 ]] && info "Overlay: $WINDOWS_OVERLAY (WINDOWS_AGENT=1)"
    warn "Building full server binary - allow ~5-10 min."
    echo ""

    export TEST_SUITE="${TEST_SUITE:-full}"
    [[ $PIVOT_MODE -eq 1 ]] && TEST_SUITE="pivot"
    info "Suite: $TEST_SUITE"
    echo ""

    local int_start; int_start=$(date +%s)
    INT_LOG="$(mktemp /tmp/rcm_int_out.XXXXXX.log)"

    # ── Pre-build images using docker build (bypasses compose bake path bugs) ──
    # Build context is . (project root). Dockerfile is copied to the context root
    # so -f uses a bare filename with no directory prefix - unambiguous in all
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

        # Server image - with pivot agents if requested
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
            --exit-code-from test-runner 2>&1 | tee "$INT_LOG" || local_exit=$?

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
    header "Phase extra - Pivot chains (test_09, re-upping containers)"
    info "Tearing down standard stack, rebuilding with BUILD_PIVOT_AGENTS=true..."
    warn "First run ~10 min; subsequent runs use cache."
    echo ""

    local int_start; int_start=$(date +%s)
    PIVOT_LOG="$(mktemp /tmp/rcm_pivot_out.XXXXXX.log)"
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
            --profile pivot up \
            --abort-on-container-exit \
            --exit-code-from test-runner 2>&1 | tee "$PIVOT_LOG" || local_exit=$?

        $COMPOSE -f docker-compose.yml -f docker-compose.pivot.yml \
            down --remove-orphans 2>/dev/null || true
        exit "$local_exit"
    ) || PIVOT_EXIT=$?

    info "Duration: $(($(date +%s) - int_start))s"
    [[ $PIVOT_EXIT -eq 0 ]] && success "Pivot phase passed." \
        || fail "Pivot phase FAILED (exit $PIVOT_EXIT)."
}

# ── String audit (OPSEC denylist gate) ───────────────────────────────────────
#
# Two layers:
#   Docker flow - the tests/docker/Dockerfile "audit" stage builds a non-debug
#     Windows agent and runs tools/string_audit.sh on it INSIDE the image
#     build; a leak fails the build of the server image. A completed
#     integration phase therefore means the gate passed.
#   Host flow   - scans the newest host-built release agent binaries in
#     target/x86_64-pc-windows-gnu/release (local cross-compile workflow).
# Hard gate: any match fails the run. Never silently passes - when neither
# layer has binaries to scan (e.g. a unit-test-only run) it warns loudly and
# skips.
run_string_audit() {
    header "Stage - String audit (OPSEC denylist scan)"

    # Docker gate: the integration build includes the audit stage (it is in
    # the server image's COPY chain), so a green integration phase already
    # ran tools/string_audit.sh against a freshly built agent.
    if [[ $RUN_INTEGRATION -eq 1 && $INT_EXIT -eq 0 ]]; then
        AUDIT_RAN=1
        info "Docker audit gate passed (tests/docker/Dockerfile 'audit' stage ran during the image build)."
    fi

    local rel_dir="target/x86_64-pc-windows-gnu/release"
    local bins=()
    if [[ -d "$rel_dir" ]]; then
        # Newest first; client*.exe (client, client_dll, client_service, ...) + stager.exe
        while IFS= read -r f; do
            bins+=("$f")
        done < <(ls -t "$rel_dir"/client*.exe "$rel_dir"/stager.exe 2>/dev/null || true)
    fi

    if [[ ${#bins[@]} -eq 0 ]]; then
        if [[ $AUDIT_RAN -eq 1 ]]; then
            # The Docker gate already ran; no host binaries to add coverage for.
            info "No host-built agent binaries in $rel_dir; relying on the Docker gate."
        else
            warn "No agent binaries found in $rel_dir - string audit SKIPPED."
            warn "Build a release agent first; on Linux-only CI this stage is expected to skip."
        fi
        return 0
    fi

    if [[ ! -x tools/string_audit.sh ]]; then
        fail "tools/string_audit.sh missing or not executable."
        AUDIT_EXIT=2
        AUDIT_RAN=1   # ran and failed - summary must not print "skipped"
        return
    fi

    AUDIT_RAN=1
    info "Auditing ${#bins[@]} binary(ies): ${bins[*]}"
    if tools/string_audit.sh "${bins[@]}"; then
        success "String audit passed - no informative strings in agent binaries."
    else
        AUDIT_EXIT=$?
        fail "String audit FAILED (exit $AUDIT_EXIT) - informative strings leak in the agent binary."
        warn "Rebuild on nightly (see rust-toolchain.toml) so builder.rs can inject -Zlocation-detail=none -Ztrim-paths."
    fi
}

# ── Machine-readable result line (AI-agent friendly) ──────────────────────────
#
# Emitted as the LAST line of every run:
#   RESULTS_JSON {"unit":"pass|fail|skip","integration":...,"pivot":...,
#                 "audit":...,"exit":N,"unit_passed":N,"unit_failed":N,
#                 "int_passed":N,"int_failed":N,"int_skipped":N,
#                 "timestamp_utc":"...","artifacts":[{"name":"...","size":N}]}
# unit_passed/unit_failed are summed from cargo's "test result: ok. N passed; N failed;"
# lines; int_* come from the test-runner's "TOTAL  N passed, N failed, N skipped" line.
emit_results_json() {
    local unit_res="skip" int_res="skip" pivot_res="skip" audit_res="skip"
    local up=0 uf=0 ip=0 ifl=0 isk=0

    if [[ $RUN_UNIT -eq 1 ]]; then
        if [[ $UNIT_EXIT -eq 0 ]]; then unit_res="pass"; else unit_res="fail"; fi
        if [[ -n "$UNIT_LOG" && -f "$UNIT_LOG" ]]; then
            up=$(grep -oE '[0-9]+ passed;' "$UNIT_LOG" 2>/dev/null | awk '{s+=$1} END{print s+0}' || true)
            uf=$(grep -oE '[0-9]+ failed;' "$UNIT_LOG" 2>/dev/null | awk '{s+=$1} END{print s+0}' || true)
        fi
    fi

    if [[ $RUN_INTEGRATION -eq 1 ]]; then
        if [[ $INT_EXIT -eq 0 ]]; then int_res="pass"; else int_res="fail"; fi
    fi
    if [[ $RUN_PIVOT_PHASE -eq 1 ]]; then
        if [[ $PIVOT_EXIT -eq 0 ]]; then pivot_res="pass"; else pivot_res="fail"; fi
    fi

    # Per-test counts: integration compose log; fall back to the pivot phase log
    # when only the pivot phase produced a test-runner TOTAL line.
    local total_log=""
    if [[ -n "$INT_LOG" && -f "$INT_LOG" ]]; then
        total_log="$INT_LOG"
    elif [[ -n "$PIVOT_LOG" && -f "$PIVOT_LOG" ]]; then
        total_log="$PIVOT_LOG"
    fi
    if [[ -n "$total_log" ]]; then
        local tline
        tline=$(grep 'TOTAL' "$total_log" 2>/dev/null | tail -1 || true)
        ip=$(echo "$tline"  | grep -oE '[0-9]+ passed'  | grep -oE '^[0-9]+' || echo 0)
        ifl=$(echo "$tline" | grep -oE '[0-9]+ failed'  | grep -oE '^[0-9]+' || echo 0)
        isk=$(echo "$tline" | grep -oE '[0-9]+ skipped' | grep -oE '^[0-9]+' || echo 0)
    fi

    if [[ $AUDIT_RAN -eq 1 ]]; then
        if [[ $AUDIT_EXIT -eq 0 ]]; then audit_res="pass"; else audit_res="fail"; fi
    fi

    # Artifacts produced by this run: dist/ files newer than the run start.
    # Lets an AI agent locate generated build outputs without parsing logs.
    local artifacts="[]"
    if [[ -d dist ]]; then
        local first=1 f sz
        artifacts="["
        while IFS= read -r f; do
            sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
            [[ $first -eq 0 ]] && artifacts+=","
            artifacts+="{\"name\":\"$f\",\"size\":$sz}"
            first=0
        done < <(find dist -type f -newermt "@${RUN_START_EPOCH}" 2>/dev/null | sort)
        artifacts+="]"
    fi

    local ts_utc; ts_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    echo "RESULTS_JSON {\"unit\":\"$unit_res\",\"integration\":\"$int_res\",\"pivot\":\"$pivot_res\",\"audit\":\"$audit_res\",\"exit\":$OVERALL,\"unit_passed\":$up,\"unit_failed\":$uf,\"int_passed\":$ip,\"int_failed\":$ifl,\"int_skipped\":$isk,\"timestamp_utc\":\"$ts_utc\",\"artifacts\":$artifacts}"
}

# ── Result persistence (AI-agent friendly) ────────────────────────────────────
#
# Writes the RESULTS_JSON payload to a stable path plus a timestamped archive
# so an agent can always read tests/results/last.json without parsing console
# output. Archive files are append-only history.
persist_results() {
    local line="$1"
    local json="${line#RESULTS_JSON }"
    local ts; ts=$(date -u +%Y%m%d-%H%M%S)
    mkdir -p tests/results
    printf '%s\n' "$json" > tests/results/last.json
    printf '%s\n' "$json" > "tests/results/result_${ts}.json"
    # With --json, stdout must end with the RESULTS_JSON line - suppress this
    # notice there. In --summary mode stdout of run_all is the log file, so
    # echoing keeps the notice in the log while the console filter drops it.
    if [[ $JSON_ONLY -eq 0 || $SUMMARY -eq 1 ]]; then
        echo "[*] Results saved to tests/results/last.json (archive: tests/results/result_${ts}.json)"
    fi
}

# ── Run ────────────────────────────────────────────────────────────────────────

run_all() {
    [[ $RUN_UNIT -eq 1 ]]        && run_unit_tests
    [[ $RUN_INTEGRATION -eq 1 ]] && run_integration_tests
    [[ $RUN_PIVOT_PHASE -eq 1 ]] && run_pivot_phase
    run_string_audit

    # ── Summary ────────────────────────────────────────────────────────────────

    OVERALL=$(( UNIT_EXIT | INT_EXIT | PIVOT_EXIT | AUDIT_EXIT ))

    header "═══ Results ═══"
    echo ""
    [[ $RUN_UNIT -eq 1 ]] && {
        [[ $UNIT_EXIT -eq 0 ]] && success "Unit        passed" || fail "Unit        FAILED"
    }
    [[ $RUN_INTEGRATION -eq 1 ]] && {
        [[ $INT_EXIT -eq 0 ]] && success "Integration  passed" || fail "Integration  FAILED"
    }
    [[ $RUN_PIVOT_PHASE -eq 1 ]] && {
        [[ $PIVOT_EXIT -eq 0 ]] && success "Pivot        passed" || fail "Pivot        FAILED"
    }
    if [[ $AUDIT_RAN -eq 1 ]]; then
        [[ $AUDIT_EXIT -eq 0 ]] && success "String audit passed" || fail "String audit FAILED"
    else
        warn "String audit skipped (no agent binaries - see above)"
    fi
    echo ""
    [[ $OVERALL -eq 0 ]] && success "All tests passed." || fail "Tests failed."

    RESULTS_LINE="$(emit_results_json)"
    echo "$RESULTS_LINE"
    persist_results "$RESULTS_LINE"
    return "$OVERALL"
}

# ── Entry point (plain or --summary) ───────────────────────────────────────────

if [[ $SUMMARY -eq 1 ]]; then
    # Terse console output for AI agents: full output goes to the log file;
    # console gets only phase headers, failing ✗ lines, TOTAL, the Results
    # block and the RESULTS_JSON line.
    LOG_FILE="${RCM_TEST_LOG:-/tmp/rcm_last_test.log}"
    set +e
    run_all >"$LOG_FILE" 2>&1
    OVERALL=$?
    set -e
    # Phase headers, script status lines, failing test ✗ lines, TOTAL lines,
    # cargo "test result:" summaries, hard errors - drop all other chatter.
    grep -aE '═══|Phase |Stage -|Clean slate|\[(•|✓|✗|!)\]|✗|TOTAL|RESULT:|test result:|^error|FAILED' \
        "$LOG_FILE" || true
    echo ""
    info "Full log: $LOG_FILE"
    grep -a 'RESULTS_JSON' "$LOG_FILE" || true
    # Keep the persistence notice as the final line unless --json requires
    # RESULTS_JSON to be the last stdout line.
    if [[ $JSON_ONLY -eq 0 ]]; then
        grep -a '^\[\*\] Results saved to ' "$LOG_FILE" || true
    fi
    exit "$OVERALL"
fi

OVERALL=0
run_all || OVERALL=$?
exit "$OVERALL"