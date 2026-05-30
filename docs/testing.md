# Testing

## Running Tests

```bash
# All tests
cargo test

# Specific test file
cargo test --test test_database
cargo test --test test_fallback
cargo test --test test_file_transfer
cargo test --test test_jobs

# Specific test
cargo test test_transform_base64_roundtrip

# With output
cargo test -- --nocapture
```

## Test Structure

### Inline Unit Tests
Located inside source files via `#[cfg(test)] mod tests`. Test private functions.

| Module | Tests | Coverage |
|--------|-------|----------|
| `traffic.rs` | 12 | Transform pipeline roundtrips, HTTP frame construction, async send/recv via duplex |
| `common.rs` | 9 | Signable bytes determinism, serde roundtrips, config deserialization, session heartbeat |
| `artifacts.rs` | 12 | Glob matching (6 patterns), secure delete lifecycle, timestomping |

### Integration Tests
Located in `tests/` directory. Test public API across modules.

| File | Tests | Coverage |
|------|-------|----------|
| `test_database.rs` | 7 | Operator CRUD, audit log, auto-recon, session notes, listeners, session IDs, webhooks |
| `test_fallback.rs` | 10 | All 4 strategies, failure tracking, dead reset, per-endpoint overrides, status summary |
| `test_file_transfer.rs` | 10 | find_all_files (5 scenarios), read/write roundtrip, directory creation, report serialization |
| `test_jobs.rs` | 7 | Spawn/complete lifecycle, ID increment, kill, purge, JSON output, stream chunks |

### Test Isolation
- Database tests use temporary SQLite files (unique UUID per test)
- File tests use `/tmp/rcm_test_*` directories (cleaned up after each test)
- Network tests use `tokio::io::duplex` (in-process, no sockets)
- Async tests use `#[tokio::test]`

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
