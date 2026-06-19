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
| `common.rs` | 9 | Signable bytes determinism, serde roundtrips, config deserialization, session heartbeat |
| `artifacts.rs` | 12 | Glob matching (6 patterns), secure delete lifecycle, timestomping |
| `transport.rs` | 9 | SNI resolution (default, override, empty), ALPN storage and encoding, TCP target formatting |
| `topology.rs` | 38 | CIDR normalisation, scoring (prefix length, interface type, flags), plan ranking, render output, multi-session conflict detection |
| `agent/dga.rs` | 21 | FNV-1a mixing determinism, domain format (dot count, charset, label length, TLD), seed isolation, window rotation, uniqueness, endpoint count/port/transport, window boundary arithmetic |
| `agent/fallback.rs` | 14 | All 4 strategies, failure tracking, all-dead reset, success clearing, per-endpoint profile override, DGA injection, static-vs-DGA priority ordering |

**Total inline unit tests: 115** (contributing to the 164 reported by `cargo test --lib`)

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

**Total integration tests: 67**

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
```

### Docker Test Suites

| Suite | Flag | What runs | Agents needed |
|-------|------|-----------|---------------|
| **smoke** | `TEST_SUITE=smoke` | Auth, RBAC, listeners, webhook, audit | No |
| **full** | default | All smoke + sessions, proxy, rportfwd, topology, hibernation queue | Yes (3: TLS, HTTP, hibernation) |
| **pivot** | `--pivot` | All full + 4-hop pivot chain stress tests | Yes (3 + chain hops) |

### Docker Integration Test Results (current)

Standard suite (130 tests):

| Test | Coverage | Result |
|------|----------|--------|
| `test_01_auth.sh` | Login, API key, rate limiting, bad credentials | 10✓ |
| `test_02_rbac.sh` | Viewer/operator/admin boundaries on every mutating endpoint | 15✓ |
| `test_03_listeners.sh` | CRUD, port validation (privileged, duplicate, reserved) | 8✓ |
| `test_04_sessions.sh` | Agent check-in, command dispatch, output polling, history, notes | 12✓ |
| `test_05_webhook.sh` | Set/get/clear, SSRF prevention | 13✓ |
| `test_06_audit.sh` | Audit log population, auto-recon CRUD | 8✓ |
| `test_07_proxy.sh` | SOCKS proxy, rportfwd API, data delivery through tunnel | 10✓ |
| `test_08_windows.sh` | Windows-specific features (skips when no Windows agent) | 1✓ 1⊘ |
| `test_09_pivot_chains.sh` | Pivot test (skips without pivot infrastructure) | 0✓ 1⊘ |
| `test_10_builder_features.sh` | SNI override in handshake, hibernation agent build | 2✓ |
| `test_11_topology.sh` | Topology plan endpoint, candidate ranking, CIDR targeting | 28✓ |
| `test_12_hibernation.sh` | Task queue API contract, enqueue, pending/cancel lifecycle, end-to-end completion | 23✓ 1⊘ |
| **TOTAL** | | **130 passed, 0 failed, 3 skipped** |

Pivot suite adds 4 more tests (134 total, 2 skipped).

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
