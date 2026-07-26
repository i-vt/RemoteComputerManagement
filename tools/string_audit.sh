#!/bin/sh
# tools/string_audit.sh - CI gate: fail if a release binary leaks informative strings.
#
# Runs strings(1) on each given binary and greps the output against the OPSEC
# denylist below: panic/build paths (src/agent/..., /cargo/registry/...,
# /rustc/...), serde field names (the whole C2Config / wire-struct schema),
# endpoint paths, Windows API names, browser paths, and protocol markers.
# A single match fails the audit.
#
# Usage:
#   tools/string_audit.sh <binary> [binary ...]
#   tools/string_audit.sh --selftest     # pipe fake strings output through the
#                                        # checker to prove it triggers
#
# Exit codes:
#   0  all audited binaries clean / selftest passed
#   1  denylist match found (audit FAILED) / selftest failed
#   2  usage error, missing file, or no strings(1) implementation available
#
# POSIX sh; no bashisms.

set -eu

usage() {
    cat >&2 <<'EOF'
Usage:
  tools/string_audit.sh <binary> [binary ...]
  tools/string_audit.sh --selftest

Exit: 0 = clean, 1 = denylist match, 2 = usage/tooling error.
EOF
}

# --- Denylist -----------------------------------------------------------------
# One fixed string per line, matched literally (grep -F). Keep in sync with
# SPEC FIX 1: every panic-path, serde field-name, endpoint, API, browser-path
# and protocol-marker literal that must never survive in a shipped agent.

DENYLIST_TMP="${TMPDIR:-/tmp}/rcm_string_audit_denylist.$$"
trap 'rm -f "$DENYLIST_TMP"' EXIT HUP INT TERM

cat > "$DENYLIST_TMP" <<'DENYLIST'
src/agent/
src/server/
/cargo/registry/
/rustc/
index.crates.io
.cargo/registry
library/core
library/std
library/alloc
called `Option::unwrap()
called `Result::unwrap()`
panicked at
thread 'main'
RUST_BACKTRACE
rust_begin_unwind
backtrace::
core::fmt
core::panicking
sleep_interval
jitter_min
jitter_max
kill_date
guard_domain
guard_hostname
guard_hour
guard_no_system
challenge_key
server_proof
auth_hmac
reg_timestamp
hibernation_mode
task_batch_size
valid_parents
sleep_mask
indirect_syscalls
stack_spoof
patch_amsi_etw
heap_encrypt
auto_pivot_port
fallback
dead_time_secs
window_secs
max_failures
use_system
user_agent
http_get
http_post
data_transform
format_http
session_id
request_id
exit_code
stream_id
computer_id
exe_id
build_id
/register
AmsiScanBuffer
EtwEventWrite
Chrome\User Data
Firefox\Profiles
file:chunk|
file:data|
JOB_FINAL:
JOB_STREAM:
KEYLOG_DUMP:
SCREENSHOT_DUMP:
rcm-agent
DENYLIST

# --- strings(1) discovery -----------------------------------------------------

find_strings() {
    if command -v strings >/dev/null 2>&1; then
        STRINGS_BIN=strings
    elif command -v llvm-strings >/dev/null 2>&1; then
        STRINGS_BIN=llvm-strings
    else
        cat >&2 <<'EOF'
ERROR: no strings(1) implementation found.
Install binutils (strings) or LLVM (llvm-strings), then re-run the audit.
The string audit is a hard CI gate - it must not be silently skipped.
EOF
        exit 2
    fi
}

# --- Core checker -------------------------------------------------------------

# audit_stream LABEL
#   Reads strings(1) output on stdin. Prints every denylist match with its
#   line number and the pattern(s) that matched. Returns 1 on any match,
#   0 when the stream is clean.
audit_stream() {
    _label=$1
    _buf="${TMPDIR:-/tmp}/rcm_string_audit_stream.$$"
    cat > "$_buf"
    _hits=$(grep -nF -f "$DENYLIST_TMP" "$_buf" || true)
    rm -f "$_buf"
    [ -z "$_hits" ] && return 0

    printf 'FAIL [%s]: denylist strings found:\n' "$_label"
    printf '%s\n' "$_hits" | while IFS= read -r _m; do
        _lineno=${_m%%:*}
        _str=${_m#*:}
        _pats=""
        while IFS= read -r _p; do
            case "$_str" in
                *"$_p"*) _pats="$_pats $_p" ;;
            esac
        done < "$DENYLIST_TMP"
        printf '  line %s: %s\n' "$_lineno" "$_str"
        printf '    pattern(s):%s\n' "$_pats"
    done
    return 1
}

# audit_file BINARY
#   Runs strings on one binary and audits the output.
#   Returns 0 clean, 1 denylist hit, 2 missing file / strings failure.
audit_file() {
    _bin=$1
    if [ ! -f "$_bin" ]; then
        printf 'ERROR: no such file: %s\n' "$_bin" >&2
        return 2
    fi
    if ! _out=$("$STRINGS_BIN" -a "$_bin" 2>/dev/null); then
        printf 'ERROR: %s failed on %s\n' "$STRINGS_BIN" "$_bin" >&2
        return 2
    fi
    if printf '%s\n' "$_out" | audit_stream "$_bin"; then
        printf 'PASS: %s (no denylist strings)\n' "$_bin"
        return 0
    fi
    return 1
}

# --- Selftest -----------------------------------------------------------------

# Simulated strings output of a LEAKY agent binary (plus benign lines).
dirty_stream() {
    printf '%s\n' \
        'MZ' \
        'kernel32.dll' \
        'src/agent/main.rs:412:9' \
        '/cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.35.0/src/runtime.rs' \
        'sleep_interval' \
        'AmsiScanBuffer' \
        'JOB_FINAL:9' \
        'C:\Users\victim\AppData\Local\Chrome\User Data\Default' \
        '/register' \
        'rcm-agent v1'
}

selftest() {
    _rc=0
    _ndeny=$(wc -l < "$DENYLIST_TMP" | tr -d ' ')
    printf 'selftest: denylist has %s patterns\n' "$_ndeny"

    # 1/3: a dirty strings output MUST fail the audit (report shown).
    printf 'selftest[1/3]: dirty stream must be rejected (report below):\n'
    if dirty_stream | audit_stream "selftest-dirty"; then
        printf 'SELFTEST FAIL: dirty stream was accepted\n' >&2
        _rc=1
    else
        printf 'selftest[1/3]: OK - dirty stream rejected\n'
    fi

    # 2/3: a clean strings output MUST pass.
    printf 'selftest[2/3]: clean stream must be accepted\n'
    if printf '%s\n' 'kernel32.dll' 'ntdll.dll' 'GetProcAddress' 'LoadLibraryW' 'MH_%s' \
        | audit_stream "selftest-clean"; then
        printf 'selftest[2/3]: OK - clean stream accepted\n'
    else
        printf 'SELFTEST FAIL: clean stream was rejected\n' >&2
        _rc=1
    fi

    # 3/3: every single denylist pattern MUST individually trigger.
    printf 'selftest[3/3]: each denylist pattern must trigger\n'
    _bad=0
    while IFS= read -r _p; do
        if printf 'xx%syy\n' "$_p" | audit_stream "selftest-pattern" >/dev/null 2>&1; then
            printf 'SELFTEST FAIL: pattern did not trigger: %s\n' "$_p" >&2
            _rc=1
            _bad=1
        fi
    done < "$DENYLIST_TMP"
    [ "$_bad" -eq 0 ] && printf 'selftest[3/3]: OK - all %s patterns trigger\n' "$_ndeny"

    if [ "$_rc" -eq 0 ]; then
        printf 'selftest: PASSED\n'
    else
        printf 'selftest: FAILED\n' >&2
    fi
    return "$_rc"
}

# --- Main ---------------------------------------------------------------------

case "${1:-}" in
    --selftest)
        selftest
        exit $?
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    "")
        usage
        exit 2
        ;;
esac

find_strings

_overall=0
for _bin in "$@"; do
    _rc=0
    audit_file "$_bin" || _rc=$?
    [ "$_rc" -ne 0 ] && _overall=$_rc
done
exit "$_overall"
