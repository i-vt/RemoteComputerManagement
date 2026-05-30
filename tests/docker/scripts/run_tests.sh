#!/usr/bin/env bash
# tests/docker/scripts/run_tests.sh — Main integration test orchestrator
#
# Runs test_*.sh scripts and produces a combined summary.
# Exit code is non-zero if any test failed.
#
# Suite filtering via TEST_SUITE env var:
#   TEST_SUITE=smoke   → auth, rbac, listeners, audit (no agents needed)
#   TEST_SUITE=full    → all tests (default)
#   TEST_SUITE=pivot   → all tests including pivot chains
#
# Unit tests are NOT run here — they run during the Docker build stage
# and fail the build on failure. This script is integration-only.

set -uo pipefail

SCRIPT_DIR="$(dirname "$0")"
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
SUITE_RESULTS=()

TEST_SUITE="${TEST_SUITE:-full}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              RCM Integration Test Suite                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "C2 URL:     ${C2_URL:-http://c2-server:8080}"
echo "Creds file: /shared/admin_creds.json"
echo "Suite:      ${TEST_SUITE}"
echo "Timestamp:  $(date -Iseconds 2>/dev/null || date)"
echo ""

# ── Classify tests into tiers ───────────────────────────────────────────
# Smoke tests need only the API (no agents).
# Full tests need agents connected.
# Pivot tests need PIVOT_TEST=1.
SMOKE_TESTS="test_01_auth test_02_rbac test_03_listeners test_05_webhook test_06_audit"
AGENT_TESTS="test_04_sessions test_07_proxy test_08_windows"
PIVOT_TESTS="test_09_pivot_chains"

should_run() {
    local name="$1"
    case "$TEST_SUITE" in
        smoke)
            echo "$SMOKE_TESTS" | grep -qw "$name"
            ;;
        full|pivot)
            # full and pivot run everything; pivot tests self-skip via PIVOT_TEST env
            return 0
            ;;
        *)
            return 0
            ;;
    esac
}

# ── Wait for agents if running agent-dependent tests ────────────────────
if [ "$TEST_SUITE" != "smoke" ]; then
    source "$SCRIPT_DIR/lib.sh"

    # Determine expected agent count
    EXPECTED_AGENTS=2  # agent-1 (TLS) + agent-2 (HTTP)
    AGENT_TIMEOUT=60

    echo "━━━ Waiting for agents ━━━"
    if wait_agents "$EXPECTED_AGENTS" "$AGENT_TIMEOUT"; then
        SUITE_RESULTS+=("agent-readiness:PASS")
    else
        echo "  WARNING: Not all agents connected. Tests that need agents may fail."
        SUITE_RESULTS+=("agent-readiness:WARN")
    fi
fi

# ── Run each integration test script ────────────────────────────────────
for test_script in "$SCRIPT_DIR"/test_*.sh; do
    [ -f "$test_script" ] || continue

    name="$(basename "$test_script" .sh)"

    if ! should_run "$name"; then
        continue
    fi

    echo ""
    echo "┌──────────────────────────────────────────"
    echo "│ Running: $name"
    echo "└──────────────────────────────────────────"

    # Run in a subshell to isolate variables but capture output
    set +e
    output=$(bash "$test_script" 2>&1)
    exit_code=$?
    set -e

    echo "$output"

    # Extract pass/fail/skip counts from the output
    p=$(echo "$output" | grep -c "  ✓" || true)
    f=$(echo "$output" | grep -c "  ✗" || true)
    s=$(echo "$output" | grep -c "  ⊘" || true)

    TOTAL_PASS=$((TOTAL_PASS + p))
    TOTAL_FAIL=$((TOTAL_FAIL + f))
    TOTAL_SKIP=$((TOTAL_SKIP + s))

    if [ "$f" -gt 0 ]; then
        SUITE_RESULTS+=("$name:FAIL($p✓ $f✗ $s⊘)")
    else
        SUITE_RESULTS+=("$name:PASS($p✓ $s⊘)")
    fi
done

# ── Summary ─────────────────────────────────────────────────────────────
TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))

echo ""
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                      TEST RESULTS                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
for result in "${SUITE_RESULTS[@]}"; do
    suite_name="${result%%:*}"
    suite_result="${result#*:}"
    printf "║  %-30s %28s ║\n" "$suite_name" "$suite_result"
done
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-30s %28s ║\n" "TOTAL" "${TOTAL_PASS} passed, ${TOTAL_FAIL} failed, ${TOTAL_SKIP} skipped"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo "RESULT: FAILED ($TOTAL_FAIL failures)"
    exit 1
else
    echo "RESULT: PASSED"
    exit 0
fi
