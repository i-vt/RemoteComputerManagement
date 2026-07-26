#!/usr/bin/env bash
# tests/docker/scripts/test_15_builder_shellcode.sh
#
# Integration tests for --format shellcode (sRDI-style DLL→shellcode).
#
# Verifies, against the live stack:
#   1. The API accepts format=shellcode (platform=windows) and the build job
#      completes
#   2. The downloaded artifact is structurally valid sRDI shellcode:
#      69-byte bootstrap, RDI stub at offset 69, DLL image at offset
#      69+2772, default user-data trailer b"None"
#   3. The b64 output encoding decodes back to the same shellcode shape
#   4. Request validation rejects shellcode on non-Windows platforms, bad
#      sc_output encodings, and malformed sc_hash values with HTTP 400
#
# Depends on: c2-server healthy, admin credentials in /shared/admin_creds.json
#
# NOTE: The shellcode build cross-compiles the agent for
# x86_64-pc-windows-gnu — first run can take several minutes. BUILD_TIMEOUT
# defaults to 600s here (vs 180s in test_10).

set -uo pipefail
source "$(dirname "$0")/lib.sh"

BUILD_TIMEOUT="${BUILD_TIMEOUT:-600}"  # seconds to wait for each build
BOOT_LEN=69
STUB_LEN=2772
DLL_OFF=$((BOOT_LEN + STUB_LEN))       # 2841 — DLL image starts here

# ── Helper: start a build and return the job ID ────────────────────────────
start_build() {
    local payload="$1"
    local resp
    resp=$(curl -s -w '\n%{http_code}' \
        -X POST "${C2_URL}/api/builder/build" \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)
    local code
    code=$(echo "$resp" | tail -1)
    echo "$code" > /tmp/.last_http_code
    echo "$resp" | sed '$d'
}

# ── Helper: poll job status until done or timeout ──────────────────────────
wait_for_build() {
    local job_id="$1"
    local deadline=$(($(date +%s) + BUILD_TIMEOUT))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        local status_resp
        status_resp=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs/${job_id}/status" 2>/dev/null || echo '{}')
        local state
        state=$(echo "$status_resp" | jq -r '.status // "unknown"')

        case "$state" in
            completed|done|success)
                echo "completed"
                return 0
                ;;
            failed|error)
                echo "failed"
                return 1
                ;;
        esac
        sleep 5
    done
    echo "timeout"
    return 1
}

# ── Helper: read <len> hex bytes at <offset> from <file>, no separators ────
byte_at() {
    od -A n -t x1 -j "$2" -N "$3" "$1" 2>/dev/null | tr -d ' \n'
}

# ── Helper: download a build artifact to a local path ──────────────────────
download_artifact() {
    local job_id="$1" out="$2"
    local code
    code=$(curl -s -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/builder/jobs/${job_id}/download" \
        -o "$out" -w '%{http_code}' 2>/dev/null)
    echo "$code" > /tmp/.last_http_code
}

# ══════════════════════════════════════════════════════
suite "Shellcode build: raw .bin artifact"
# ══════════════════════════════════════════════════════

RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "windows",
    "transport": "tls",
    "format": "shellcode",
    "sc_output": "bin",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true
}')
assert_http "shellcode build request accepted" "202"

JOB_BIN=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for shellcode build" "" "$JOB_BIN"

if [ -n "$JOB_BIN" ]; then
    BIN_RESULT=$(wait_for_build "$JOB_BIN")
    assert_eq "shellcode build completes successfully" "completed" "$BIN_RESULT"

    if [ "$BIN_RESULT" = "completed" ]; then
        SC=/tmp/rcm_test_sc.bin
        download_artifact "$JOB_BIN" "$SC"
        assert_http "shellcode artifact downloads" "200"

        SIZE=$(stat -c %s "$SC" 2>/dev/null || echo 0)
        assert_ne "artifact is non-empty" "0" "$SIZE"

        # Bootstrap structure (see src/shellcode.rs for the layout)
        assert_eq "byte 0 is call \$+5 (0xE8)"        "e8"     "$(byte_at "$SC" 0 1)"
        assert_eq "byte 5 is pop rcx (0x59)"          "59"     "$(byte_at "$SC" 5 1)"
        assert_eq "byte 9 is mov edx,hash (0xBA)"     "ba"     "$(byte_at "$SC" 9 1)"
        assert_eq "RDI stub prologue at offset 69"    "488bc4" "$(byte_at "$SC" 69 3)"
        assert_eq "call rel32 target is offset 69"    "05000000" "$(byte_at "$SC" 60 4)"

        # DLL image must start exactly after bootstrap + stub
        assert_eq "MZ magic at DLL offset (2841)"     "4d5a"   "$(byte_at "$SC" $DLL_OFF 2)"

        # Default user data (b"None") is the trailer
        assert_eq "user-data trailer is 'None'"       "None"   "$(tail -c 4 "$SC")"

        # Size sanity: header + a real DLL (agents are megabytes) + trailer
        if [ "$SIZE" -gt $((DLL_OFF + 512)) ]; then
            echo "  ✓ artifact size plausible ($SIZE bytes)"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo "  ✗ artifact size implausible ($SIZE bytes, DLL looks truncated)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi
fi

# ══════════════════════════════════════════════════════
suite "Shellcode build: base64 encoding round-trips"
# ══════════════════════════════════════════════════════

RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "windows",
    "transport": "tls",
    "format": "shellcode",
    "sc_output": "b64",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true
}')
assert_http "b64 shellcode build request accepted" "202"

JOB_B64=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for b64 build" "" "$JOB_B64"

if [ -n "$JOB_B64" ]; then
    B64_RESULT=$(wait_for_build "$JOB_B64")
    assert_eq "b64 shellcode build completes" "completed" "$B64_RESULT"

    if [ "$B64_RESULT" = "completed" ]; then
        B64F=/tmp/rcm_test_sc.b64.txt
        download_artifact "$JOB_B64" "$B64F"
        assert_http "b64 artifact downloads" "200"

        # Only base64 alphabet + optional newline in the file
        NONB64=$(tr -d 'A-Za-z0-9+/=\n' < "$B64F" | wc -c)
        assert_eq "file contains only base64 characters" "0" "$NONB64"

        # Decode and verify the same structure as the raw artifact
        if base64 -d "$B64F" > /tmp/rcm_test_sc_decoded.bin 2>/dev/null; then
            echo "  ✓ base64 decodes cleanly"
            PASS_COUNT=$((PASS_COUNT + 1))
            DEC=/tmp/rcm_test_sc_decoded.bin
            assert_eq "decoded byte 0 is 0xE8"       "e8"     "$(byte_at "$DEC" 0 1)"
            assert_eq "decoded stub prologue at 69"  "488bc4" "$(byte_at "$DEC" 69 3)"
            assert_eq "decoded MZ at DLL offset"     "4d5a"   "$(byte_at "$DEC" $DLL_OFF 2)"
            assert_eq "decoded trailer is 'None'"    "None"   "$(tail -c 4 "$DEC")"
        else
            echo "  ✗ base64 -d failed on $B64F"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi
fi

# ══════════════════════════════════════════════════════
suite "Shellcode request validation"
# ══════════════════════════════════════════════════════

# Non-Windows platform must be rejected before a build ever starts
RESP=$(start_build '{
    "host": "c2-server", "port": "4443",
    "platform": "linux", "transport": "tls",
    "format": "shellcode"
}')
assert_http "shellcode on linux rejected" "400"
assert_contains "error points at platform=windows" "platform=windows" "$RESP"

RESP=$(start_build '{
    "host": "c2-server", "port": "4443",
    "platform": "macos", "transport": "tls",
    "format": "shellcode"
}')
assert_http "shellcode on macos rejected" "400"

# Unknown output encoding
RESP=$(start_build '{
    "host": "c2-server", "port": "4443",
    "platform": "windows", "transport": "tls",
    "format": "shellcode", "sc_output": "pdf"
}')
assert_http "invalid sc_output rejected" "400"
assert_contains "error names sc_output" "sc_output" "$RESP"

# Malformed hash (not decimal, not 0x-hex)
RESP=$(start_build '{
    "host": "c2-server", "port": "4443",
    "platform": "windows", "transport": "tls",
    "format": "shellcode", "sc_hash": "0xZZZ"
}')
assert_http "malformed sc_hash rejected" "400"
assert_contains "error names sc_hash" "sc_hash" "$RESP"

# Decimal hash is valid alongside 0x-hex
RESP=$(start_build '{
    "host": "c2-server", "port": "4443",
    "platform": "linux", "transport": "tls",
    "format": "shellcode", "sc_hash": "3735928559"
}')
assert_http "decimal hash parses (fails only on platform)" "400"
assert_contains "failure is platform, not hash" "platform=windows" "$RESP"

print_summary