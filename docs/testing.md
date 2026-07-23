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
| `common.rs` | 13 | Signable bytes determinism, serde roundtrips, C2Config deserialization (minimal, fallback, evasion, guardrails), auto-pivot port, profile/proxy defaults, session heartbeat |
| `database.rs` | 11 | Hibernation task queue: UUID enqueue, per-session claiming, batch limit, created-at ordering, complete/fail status, list, clear |
| `file_transfer.rs` | 14 | Path-traversal rejection, base64 validation, chunk finality arithmetic, root-name sanitisation, chunk bounds and size limits |
| `transport.rs` | 10 | SNI resolution (default, override, empty, none), ALPN storage, ordering and rustls byte encoding, TCP target formatting, HTTP transport error-not-panic |
| `topology.rs` | 38 | CIDR normalisation, scoring (prefix length, interface type, flags), plan ranking, render output, multi-session conflict detection |
| `shellcode.rs` | 6 | Bootstrap size/layout, embedded immediates (hash, offsets, flags), rejection of non-PE/32-bit/EXE/PE32 inputs, base64 RFC 4648 vectors, hex and C-array formatting |
| `rdi_stub.rs` | 2 | Stub size pinned to 2772 bytes, prologue bytes (guards against truncation when regenerating) |
| `agent/dga.rs` | 21 | FNV-1a mixing determinism, domain format (dot count, charset, label length, TLD), seed isolation, window rotation, uniqueness, endpoint count/port/transport, window boundary arithmetic |
| `agent/fallback.rs` | 14 | All 4 strategies, failure tracking, all-dead reset, success clearing, per-endpoint profile override, DGA injection, static-vs-DGA priority ordering |
| `agent/hibernation.rs` | 15 | Sleep-interval math, jitter bounds, batch-size clamping, backoff growth and 300 s cap, kill-date triggers, SNI/ALPN passthrough |
| `agent/artifacts.rs` | 12 | Glob matching (7 patterns), secure delete lifecycle, timestomping |
| `agent/evasion/detection.rs` | 7 | VM-detection determinism, parent-process allowlist semantics, always-permissive non-Windows stubs |
| `agent/evasion/heap.rs` | 23 | HEAP_ENTRY size/alignment/offsets vs Win32 x64, XOR cipher properties, AES-256-GCM stream roundtrip, nonce derivation determinism and uniqueness, non-Windows stubs |
| `agent/evasion/patching.rs` | 9 | AMSI/ETW patching and ntdll unhooking: non-Windows errors, no-panic guarantees, success-message contents |
| `agent/evasion/sleep.rs` | 10 | .text section discovery (non-null, plausible size, deterministic), Ekko sleep, spoofed-stack sleep duration behaviour |
| `agent/handlers/config.rs` | 5 | sleep command argument validation, beacon mode active/passive |
| `agent/handlers/evasion.rs` | 4 | patch_all returns three results, platform guards, syscall-check output, heap decrypt-without-encrypt error |
| `agent/handlers/execution.rs` | 2 | shell echo roundtrip, bad-command handling |
| `agent/handlers/files.rs` | 16 | timestomp/ADS argument validation, chunked write: field count, base64 validation, first-chunk truncation, multi-chunk ordering, binary fidelity, parent-dir creation, zero-byte files |
| `agent/handlers/persistence.rs` | 30 | Argument splitting/trimming helpers, usage errors for every persist subcommand, platform guards (Windows/Linux/macOS) that error without panicking |
| `agent/handlers/process.rs` | 3 | injection argument, PID and base64 validation |
| `agent/persistence/linux.rs` | 36 | stable_drop (copy fidelity, exec bit, idempotence), systemd unit generation/install/remove, profile sentinel-block install/remove with content preservation |
| `agent/scripting/python.rs` | 35 | Portable-python discovery, temp-script writing, venv lifecycle, pip JSON, exec (arithmetic, multiline, JSON, stdlib, timeout), sessions, Rhai bridge bindings |
| `api/routes/builder.rs` | 81 | Build-request validation (host/port, platform, transport, format, shellcode guards, jitter, guard hours), CLI argument assembly (46 tests), serde defaults (evasion, guardrails, auto-pivot) |
| `api/routes/extensions.rs` | 5 | safe_name validator: plain names accepted, empty/`..`/slashes/null byte rejected |
| `api/routes/hosts.rs` | 29 | ext:load argument base64 re-encoding and search-dir resolution, traversal rejection, path and base64 validators, chunk-request deserialization |

**Total inline unit tests: 463** (contributing to the count reported by `cargo test --lib`)

### Integration Tests
Located in `tests/` directory. Test the public API across module boundaries.

| File | Tests | Coverage |
|------|-------|----------|
| `test_database.rs` | 7 | Operator CRUD (with hashed API key round-trip), audit log, auto-recon, session notes, listeners, session ID allocation, webhooks |
| `test_fallback.rs` | 18 | All 4 strategies, weighted random, failure tracking, dead reset, success clearing, per-endpoint profile override, DGA endpoint injection, DGA priority ordering, status summary |
| `test_dga.rs` | 20 | Determinism, label format validation, charset, length bounds, TLD selection, seed isolation, campaign isolation, adjacent-window divergence, window boundary arithmetic, endpoint count/port/transport, unique hostnames, zero-count edge case |
| `test_file_transfer.rs` | 10 | find_all_files (5 scenarios), read/write roundtrip, directory creation, report serialization |
| `test_jobs.rs` | 7 | Spawn/complete lifecycle, ID increment, kill, purge, JSON output (parsed not string-searched), stream chunks |
| `test_transport.rs` | 5 | SNI stored from config, TCP plain connect (error not panic), named pipe non-Windows error, target address formatting |
| `test_shellcode.rs` | 24 | Golden vectors vs sRDI reference (stub SHA-256, full-blob SHA-256, exact bootstrap bytes), determinism, layout scaling, PE validation edge cases, encoders (base64 roundtrip, hex, C array), builder CLI (help text, platform guard, hash parsing, sc-output enum, --sni/--alpn alias regression) |
| `test_download.rs` | 16 | Chunked download roundtrips (empty, single byte, all 256 byte values, chunk-boundary sizes, 1 MB in 64 KB chunks), overwrite/truncate semantics, final-chunk signalling |
| `test_upload.rs` | 14 | Chunked upload roundtrips and boundary sizes, overwrite semantics, out-of-order delivery fails without corruption, concurrent uploads to different paths isolated |
| `test_recursive_download.rs` | 7 | Nested-tree fixtures, 1 GB single file, metadata named after root, Windows path normalisation, corrupted transfer fails the hash check |
| `test_evasion.rs` | 16 | Symbol resolution for detection/patching/sleep modules, non-Windows permissive stubs and error messages, suspend/resume safety, sleep-duration behaviour |
| `test_extension.rs` | 25 | Extension CRUD over the API, viewer-role 403, path traversal blocked, non-.rhai files filtered from listings |
| `test_keylogger.rs` | 9 | Buffer init (idempotent), start/stop never panic, log retrieval, thread-safe buffer access |
| `test_persistence.rs` | 37 | OS guards for every persist technique, on-disk systemd install (unit directives, wants symlink, executable stable binary), profile sentinel lifecycle, removal cleans up |
| `test_python_bridge.rs` | 27 | Interpreter discovery, exec (arithmetic, multiline, JSON, file, syntax error, timeout), venv create/exec/delete, pip install/list, session lifecycle |
| `test_scripting_crypto_compress.rs` | 48 | SHA-256/MD5/HMAC RFC vectors, CRC32, FNV-1a, base64/hex, XOR, AES-GCM and AES-128-CBC (PBKDF2), keygen, UUID, gzip and ZIP roundtrips |
| `test_scripting_io_fs.rs` | 30 | fs read/write/ls, io bytes/copy/move/delete/mkdir/stat, system env/exec/procs/sleep, sysinfo hostname/user/network/uptime/disk |
| `test_scripting_network_dns.rs` | 21 | DNS resolve/TXT, TCP connect/timeout, UDP roundtrip, HTTP GET/POST, exec detach, evasion bindings (mutex, timing, AV/VM/debugger detect) |
| `test_scripting_process_memory.rs` | 17 | Elevation check, spawn/kill lifecycle, env, token-steal guard, procinfo path/parent/cmdline/user/modules, memory regions/scan/read/write |
| `test_scripting_search_state.rs` | 31 | grep (single/recursive/invalid regex), find_files glob/depth, regex match/findall, JSON path get, state set/get/delete/keys/clear persistence, loader exec_script, credential sweep |
| `test_signing.rs` | 6 | Ed25519 command signing: valid verifies, tampered command and wrong key rejected, replay counter ordering, malformed signatures never panic |
| `test_streaming_zip.rs` | 9 | Empty/single/multi/nested/binary/large archives, local-file-header signature, cursor-vs-vec output equivalence |
| `test_utils.rs` | 19 | shell exec (stdout/stderr separation, exit codes, pipes, long output, timeout), process list contains self, network interfaces, self-destruct guards |

**Total integration tests: 423**

### Test Isolation
- Database tests use temporary SQLite files (unique UUID per test, `/tmp/rcm_test_*.db`)
- File tests use `/tmp/rcm_test_*` directories (cleaned up after each test)
- Network tests use `tokio::io::duplex` (in-process, no sockets)
- DGA and fallback tests are fully deterministic (fixed seeds, fixed window indices)
- Async tests use `#[tokio::test]`

## Docker Integration Tests

The Docker test environment builds the full project, runs unit and integration tests as a build gate, then starts a team server with live agents and executes end-to-end tests against every API surface.

```bash
# From project root — all phases
./run_tests.sh --all

# Unit tests only
./run_tests.sh

# Integration tests only (standard)
./run_tests.sh --integration

# Integration + pivot chains
./run_tests.sh --pivot

# With Windows overlay (sets WINDOWS_AGENT=1 for test_08)
./run_tests.sh --windows

# Single unit module
./run_tests.sh --module dga
./run_tests.sh --module fallback
./run_tests.sh --module shellcode
```

### Docker Test Suites

| Suite | Flag | What runs | Agents needed |
|-------|------|-----------|---------------|
| **smoke** | `TEST_SUITE=smoke` | Auth, RBAC, listeners, webhook, audit | No |
| **full** | default | All smoke + sessions, proxy, rportfwd, topology, hibernation queue, persistence, Python bridge, builder guardrails/shellcode | Yes (3: TLS, HTTP, hibernation) |
| **pivot** | `--pivot` | All full + 4-hop pivot chain stress tests | Yes (3 + chain hops) |

### Docker Integration Tests (current)

Standard suite (16 scripts, 411 checks):

| Test | Coverage | Checks |
|------|----------|--------|
| `test_01_auth.sh` | Login, API key, rate limiting, bad credentials | 10 |
| `test_02_rbac.sh` | Viewer/operator/admin boundaries on every mutating endpoint | 14 |
| `test_03_listeners.sh` | CRUD, port validation (privileged, duplicate, reserved) | 8 |
| `test_04_sessions.sh` | Agent check-in, command dispatch, output polling, history, notes | 12 |
| `test_05_webhook.sh` | Set/get/clear, SSRF prevention | 13 |
| `test_06_audit.sh` | Audit log population, auto-recon CRUD | 8 |
| `test_07_proxy.sh` | SOCKS proxy, rportfwd API, data delivery through tunnel | 9 |
| `test_08_windows.sh` | Windows-specific features (checks skip individually when no Windows agent connects) | 50 |
| `test_09_pivot_chains.sh` | 4-hop pivot chains, per-hop commands/proxy/rportfwd (skips without `--pivot` infrastructure) | 26 |
| `test_10_builder_features.sh` | SNI override in handshake, hibernation agent build | 14 |
| `test_11_builder_evasion_guardrails.sh` | Evasion (sleep_mask, syscalls, stack spoof, AMSI/ETW, heap encrypt) and guardrail (domain, hostname, hours, no_system) builder fields: one awaited end-to-end build plus the 400/202 validation matrix | 41 |
| `test_11_topology.sh` | Topology plan endpoint, candidate ranking, CIDR targeting | 22 |
| `test_12_hibernation.sh` | Task queue API contract, enqueue, pending/cancel lifecycle, end-to-end completion | 22 |
| `test_13_persistence.sh` | persist:* command family through a live agent: install changes real OS state, remove undoes it, stable drop survives source deletion, platform guards surface over the wire | 80 |
| `test_14_python_extension.sh` | Python scripting bridge via Rhai: discovery, exec, venv lifecycle, pip, sessions, bootstrap/ensure, offensive library check | 52 |
| `test_15_builder_shellcode.sh` | Shellcode build via API (raw + base64), artifact structure validation (bootstrap/stub/DLL offsets), request validation rejects (non-Windows, bad encoding, bad hash) | 30 |
| **TOTAL** | | **411 checks** |

The pivot suite (`--pivot`) runs the same scripts with pivot-chain agents built, so `test_09_pivot_chains.sh` executes its 26 checks instead of skipping; `--windows` enables `test_08_windows.sh` checks against a Windows Docker host.

### Unit Test Build Gate

Unit and integration tests run during the Docker build in a dedicated stage. If any test fails, the Docker build fails and no images are produced:

```dockerfile
FROM builder AS unit-test
COPY src/ ./src/
COPY tests/ ./tests/
RUN cargo test --no-run --locked   # compile gate
RUN cargo test --lib --tests       # run gate
```

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

Classify in `run_tests.sh`:
- `SMOKE_TESTS` — API-only, no agents needed
- `AGENT_TESTS` — needs connected agents
- `PIVOT_TESTS` — needs pivot chain infrastructure
