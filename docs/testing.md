# Testing

## Running Tests

```bash
# All unit + integration tests
cargo test

# Library unit tests only
cargo test --lib

# Specific integration test file
cargo test --test test_database
cargo test --test test_fallback
cargo test --test test_dga
cargo test --test test_file_transfer
cargo test --test test_jobs
cargo test --test test_transport

# Specific test by name
cargo test test_transform_base64_roundtrip
cargo test dga::tests::domain_is_deterministic

# With output
cargo test -- --nocapture
```

## Test Structure

### Inline Unit Tests
Located inside source files via `#[cfg(test)] mod tests`. Test private functions and internal logic.

| Module | Tests | Coverage |
|--------|-------|----------|
| `traffic.rs` | 12 | Transform pipeline roundtrips, HTTP frame construction, async send/recv via duplex |
| `common.rs` | 24 | Signable bytes determinism, serde roundtrips, config deserialization, session heartbeat |
| `artifacts.rs` | 12 | Glob matching (6 patterns), secure delete lifecycle, timestomping |
| `transport.rs` | 10 | SNI resolution (default, override, empty), ALPN storage and encoding, TCP target formatting |
| `topology.rs` | 38 | CIDR normalisation, scoring (prefix length, interface type, flags), plan ranking, render output, multi-session conflict detection |
| `agent/dga.rs` | 21 | FNV-1a mixing determinism, domain format (dot count, charset, label length, TLD), seed isolation, window rotation, uniqueness, endpoint count/port/transport, window boundary arithmetic |
| `agent/fallback.rs` | 16 | All 4 strategies, failure tracking, all-dead reset, success clearing, per-endpoint profile override, DGA injection + runtime window rotation, static-vs-DGA priority ordering |
| `shellcode.rs` | 13 | Bootstrap size/layout, embedded immediates (hash, offsets, flags), rejection of non-PE/32-bit/EXE/PE32 inputs, base64 RFC 4648 vectors, hex and C-array formatting |
| `rdi_stub.rs` | 2 | Stub size pinned to 2772 bytes, prologue bytes (guards against truncation when regenerating) |

These are only the largest clusters - the same pattern exists in the API
routes, persistence handlers, evasion, hibernation, scripting (including 35
Python-bridge tests), and RCM packaging modules.

**Total inline unit tests: 767** (`#[test]` + `#[tokio::test]` across `src/`;
the count reported by `cargo test --lib` is lower on Linux because
Windows-gated tests do not compile there)

### Integration Tests
Located in `tests/` directory. Test the public API across module boundaries.

| File | Tests | Coverage |
|------|-------|----------|
| `test_database.rs` | 11 | Operator CRUD (with hashed API key round-trip), audit log, auto-recon, session notes, listeners, session ID allocation, webhooks |
| `test_fallback.rs` | 18 | All 4 strategies, weighted random, failure tracking, dead reset, success clearing, per-endpoint profile override, DGA endpoint injection, DGA priority ordering, status summary |
| `test_dga.rs` | 20 | Determinism, label format validation, charset, length bounds, TLD selection, seed isolation, campaign isolation, adjacent-window divergence, window boundary arithmetic, endpoint count/port/transport, unique hostnames, zero-count edge case |
| `test_file_transfer.rs` | 10 | find_all_files (5 scenarios), read/write roundtrip, directory creation, report serialization |
| `test_jobs.rs` | 12 | Spawn/complete lifecycle, ID increment, kill, purge, JSON output (parsed not string-searched), stream chunks |
| `test_transport.rs` | 5 | SNI stored from config, TCP plain connect (error not panic), named pipe non-Windows error, target address formatting |
| `test_shellcode.rs` | 24 | Golden vectors vs sRDI reference (stub SHA-256, full-blob SHA-256, exact bootstrap bytes), determinism, layout scaling, PE validation edge cases, encoders (base64 roundtrip, hex, C array), builder CLI (help text, platform guard, hash parsing, sc-output enum, --sni/--alpn alias regression) |
| `test_persistence.rs` | 41 | All persist:* handlers incl. argument validation and platform gates |
| `test_evasion.rs` | 16 | Evasion handler behavior, guardrails, sleep-mask mapping |
| `test_python_bridge.rs` | 27 | Python install/exec/venv/pip bindings |
| `test_scripting_*.rs` (5 files) | 147 | Scripting engine: crypto/compress, io/fs, network/dns, process/memory, search/state |
| `test_w1_*` / `test_w2_*` / `test_w3_*` (13 files) | 151 | Regression waves: builder, menu, server state, auth, agent, HTTP, coverage |
| `rcm_spec.rs` / `rcm_regression.rs` / `test_rcm_meta.rs` | 23 | RCM Data Collection & Packaging spec conformance |
| `test_upload.rs` / `test_download.rs` / `test_recursive_download.rs` | 37 | Chunked transfer paths (one 1 GiB download test is `#[ignore]`d deliberately) |
| Other (`test_config`, `test_keylogger`, `test_signing`, `test_pivot`, `test_utils`, `test_strcrypt`, `test_streaming_zip`, `test_extension`, `test_response_pipeline`) | 94 | Config tree, keylogger buffer, ed25519 command signing, pivot frames, utils, string cryptor, streaming ZIP, extension engine, response pipeline |

**Total integration-file tests: 636** across 43 files in `tests/`

### Test Isolation
- Database tests use temporary SQLite files (unique UUID per test, `/tmp/rcm_test_*.db`)
- File tests use `/tmp/rcm_test_*` directories (cleaned up after each test)
- Network tests use `tokio::io::duplex` (in-process, no sockets)
- DGA and fallback tests are fully deterministic (fixed seeds, fixed window indices)
- Async tests use `#[tokio::test]`

## Docker Integration Tests

The Docker test environment builds the full project, runs unit and integration tests as a build gate, then starts a team server with live agents and executes end-to-end tests against every API surface.

```bash
# From project root - all phases
./run_tests.sh --all

# Unit tests only
./run_tests.sh

# Integration tests only (standard)
./run_tests.sh --integration

# Integration + pivot chains
./run_tests.sh --pivot

# With Windows overlay (sets WINDOWS_AGENT=1 for test_08)
./run_tests.sh --windows

# Single unit module (valid: topology, transport, database, hibernation,
# interface, extension, dga, fallback, shellcode)
./run_tests.sh --module dga
./run_tests.sh --module fallback
./run_tests.sh --module shellcode
```

`./run_tests.sh` with no `--module` runs the `unit-all` service: `cargo test`
with no filter (lib + every `tests/*.rs` binary).

### Docker Test Suites

| Suite | Flag | What runs | Agents needed |
|-------|------|-----------|---------------|
| **smoke** | `TEST_SUITE=smoke` | Auth, RBAC, listeners, webhook, audit | No |
| **full** | default | All smoke + sessions, proxy, rportfwd, topology, hibernation queue | Yes (3: TLS, HTTP, hibernation) |
| **pivot** | `--pivot` | All full + 4-hop pivot chain stress tests | Yes (3 + chain hops) |

### Docker Integration Test Scripts

18 scripts (`test_01` - `test_18`):

| Script | Coverage |
|--------|----------|
| `test_01_auth.sh` | Login, API key, rate limiting, bad credentials |
| `test_02_rbac.sh` | Viewer/operator/admin boundaries on every mutating endpoint |
| `test_03_listeners.sh` | CRUD, port validation (privileged, duplicate, reserved) |
| `test_04_sessions.sh` | Agent check-in, command dispatch, output polling, history, notes |
| `test_05_webhook.sh` | Set/get/clear, SSRF prevention |
| `test_06_audit.sh` | Audit log population, auto-recon CRUD |
| `test_07_proxy.sh` | SOCKS proxy, rportfwd API, data delivery through tunnel |
| `test_08_windows.sh` | Windows-specific features (skips when no Windows agent) |
| `test_09_pivot_chains.sh` | Multi-hop pivot chains (pivot suite only) |
| `test_10_builder_features.sh` | SNI override in handshake, hibernation agent build |
| `test_11_topology.sh` | Topology plan endpoint, candidate ranking, CIDR targeting |
| `test_12_hibernation.sh` | Task queue API contract, enqueue, pending/cancel lifecycle, end-to-end completion |
| `test_13_persistence.sh` | persist:* install/list/remove against a live agent |
| `test_14_python_extension.sh` | Python bridge end-to-end (bootstrap, venv, exec) |
| `test_15_builder_shellcode.sh` | Shellcode build via API (raw + base64), artifact structure validation (bootstrap/stub/DLL offsets), request validation rejects |
| `test_16_builder_evasion_guardrails.sh` | Builder evasion flags and guardrail baking |
| `test_17_stager.sh` | Stager build and `/stage/<build_id>` HMAC-authenticated fetch |
| `test_18_guardrails.sh` | Guardrail enforcement (domain/hostname/hours/parent) on live agents |

Latest recorded run (`tests/results/last.json`): **262 passed, 0 failed,
6 skipped** (skips are environment-dependent, e.g. no Windows agent).

Two scripts have strict modes for CI:

- `STAGE_STRICT=1` (test_17): contract-pending stager assertions become hard
  failures instead of loud skips. Default `0`.
- `GUARD_STRICT=1` (test_18): guardrail enforcement assertions become hard
  pass/fail. Default `0` reports enforcement gaps as loud skips.

### Unit Test Build Gate

The Rust test suite runs during the image build in a dedicated stage of the
root Dockerfile; a failing test fails the image build:

```dockerfile
FROM build AS test
RUN cargo +nightly-2026-08-22 test --release --lib 2>&1
```

The root image gates on `--lib` only; the full `cargo test` (including every
`tests/*.rs` binary) runs as the `unit-all` service in
`tests/docker/docker-compose.unit.yml`, and a later stage runs
`tools/string_audit.sh` over the built Windows agent, failing the image if
any path or Rust fingerprint string leaked.

### Three Agents in the Integration Stack

The integration stack runs three agents simultaneously:

| Container | Transport | Mode | Purpose |
|-----------|-----------|------|---------|
| `agent-1` | TLS :4443 | Persistent | Standard command execution, proxy, rportfwd |
| `agent-2` | HTTP :4480 | Persistent | HTTP transport coverage, topology |
| `agent-hibernation` | TLS :4443 | Hibernation | Task queue tests (test_12), builder feature tests (test_10) |

## Writing New Tests

### Unit test in a module
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        assert_eq!(my_private_fn(1, 2), 3);
    }
}
```

### Integration test
Create `tests/test_myfeature.rs`:
```rust
use rcm::my_module;

#[test]
fn test_something() {
    let result = my_module::public_function();
    assert!(result.is_ok());
}
```

### Async test
```rust
#[tokio::test]
async fn test_async_thing() {
    let result = some_async_fn().await;
    assert_eq!(result, expected);
}
```

### Docker integration test
Create `tests/docker/scripts/test_NN_name.sh`. Source `lib.sh` for helpers:

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

suite "My feature works"
RESP=$(api_get "/api/my-endpoint")
assert_http "returns 200" "200"
assert_contains "has expected field" "my_value" "$RESP"
```

Available helpers: `api_get`, `api_post`, `api_delete`, `login_as`, `wait_agents`, `assert_eq`, `assert_ne`, `assert_contains`, `assert_http`, `skip`, `suite`.

Classify in `tests/docker/scripts/run_tests.sh`:
- `SMOKE_TESTS` - API-only, no agents needed
- `AGENT_TESTS` - needs connected agents
- `PIVOT_TESTS` - needs pivot chain infrastructure

Unclassified scripts default to the agent tier (with a NOTE in the output),
so a new test always runs in the full and pivot suites even if you forget to
classify it.