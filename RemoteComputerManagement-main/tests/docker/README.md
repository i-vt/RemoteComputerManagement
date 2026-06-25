# Integration Testing

Docker Compose environment that builds the full project, runs unit tests as a build gate, then starts a team server with agents and runs integration tests against every API surface.

## Test Architecture

```
                    ┌─────────────────────────────────┐
                    │        Docker Build              │
                    │  ┌──────────┐   ┌────────────┐  │
  cargo test fails  │  │ builder  │──▶│ unit-test   │──┼──▶ BUILD FAILS
  = build fails     │  │ (compile)│   │ cargo test  │  │
                    │  └──────────┘   └─────┬──────┘  │
                    │                       │         │
                    │                 ┌─────▼──────┐  │
                    │                 │  agents     │  │
                    │                 │ (build bins)│  │
                    │                 └─────┬──────┘  │
                    │                       │         │
                    │                 ┌─────▼──────┐  │
                    │                 │  server /   │  │
                    │                 │  agent imgs │  │
                    │                 └────────────┘  │
                    └─────────────────────────────────┘
                                    │
                    ┌───────────────▼─────────────────┐
                    │      Docker Compose              │
                    │  ┌──────────┐  ┌─────────────┐  │
                    │  │c2-server │◀─│ agent-1/2   │  │
                    │  └────┬─────┘  └─────────────┘  │
                    │       │                          │
                    │  ┌────▼──────────────────────┐  │
                    │  │ test-runner (bash/curl/jq) │  │
                    │  │ integration tests only     │  │
                    │  └───────────────────────────┘  │
                    └─────────────────────────────────┘
```

**Key principle:** Unit tests run during the Docker build and fail the build on failure. The Compose stack only runs integration tests — it cannot produce a green result while Rust tests are broken.

## Quick Start

```bash
cd tests/docker

# Full suite (builds, runs unit tests, then integration tests):
docker compose up --build --abort-on-container-exit --exit-code-from test-runner

# Smoke suite (API-only tests, no agents needed, fast feedback):
TEST_SUITE=smoke docker compose up --build --abort-on-container-exit --exit-code-from test-runner

# Pivot suite (includes 4-hop pivot chain stress tests):
docker compose -f docker-compose.yml -f docker-compose.pivot.yml \
  --profile pivot up --build --abort-on-container-exit --exit-code-from test-runner
```

The exit code is `0` if all tests pass, non-zero otherwise. CI systems can use this directly.

## Test Suites

| Suite | Command | What runs | Agents needed |
|-------|---------|-----------|---------------|
| **smoke** | `TEST_SUITE=smoke docker compose up ...` | Auth, RBAC, listeners, webhook, audit | No |
| **full** | `docker compose up ...` (default) | All of smoke + sessions, proxy, rportfwd | Yes (2) |
| **pivot** | `docker compose -f ... -f pivot.yml --profile pivot up ...` | All of full + 4-hop pivot chains + stress | Yes (2 + chain hops) |

### Unit tests (build gate)

Unit tests run during the Docker build in a dedicated `unit-test` stage:

```dockerfile
FROM builder AS unit-test
RUN cargo test --lib --tests
```

If any test fails, the Docker build fails and no images are produced. You can also run them directly:

```bash
cargo test --lib --tests
```

## Agent Readiness

The test runner polls the `/api/hosts` endpoint for the expected number of agents instead of using fixed sleeps. This eliminates flakiness across machines with different performance characteristics. The `wait_agents` helper in `lib.sh` handles this:

```bash
# Wait for 2 agents, timeout after 60s
wait_agents 2 60
```

## Architecture

```
┌────────────┐        ┌─────────────┐
│test-runner  │───────▶│  c2-server  │◀───── agent-1 (TLS :4443)
│ curl + jq   │  API   │  API  :8080 │◀───── agent-2 (HTTP :4480)
│ bash tests  │ :8080  │  TLS  :4443 │
└────────────┘        │  HTTP :4480 │
                      └──────┬──────┘
┌────────────┐               │
│mock-service │  (nginx, returns known payload for rportfwd)
│  :80        │
└────────────┘
┌────────────┐
│webhook-sink│  (python, captures POST payloads to /webhooks/)
│  :9999     │
└────────────┘
```

## What Gets Tested

| Suite | File | Tier | Coverage |
|-------|------|------|----------|
| **Auth** | `test_01_auth.sh` | smoke | Login, API key flow, rate limiting, bad credentials |
| **RBAC** | `test_02_rbac.sh` | smoke | Viewer/operator/admin boundaries on every mutating endpoint |
| **Listeners** | `test_03_listeners.sh` | smoke | CRUD, port validation (privileged, duplicate, reserved) |
| **Sessions** | `test_04_sessions.sh` | full | Agent check-in, command dispatch, output polling, history, notes |
| **Webhook** | `test_05_webhook.sh` | smoke | Set/get/clear, SSRF prevention |
| **Audit** | `test_06_audit.sh` | smoke | Audit log population, auto-recon CRUD |
| **Proxy** | `test_07_proxy.sh` | full | SOCKS proxy, rportfwd, data delivery, viewer RBAC |
| **Windows** | `test_08_windows.sh` | full | Windows-specific features (requires WINDOWS_AGENT=1) |
| **Pivots** | `test_09_pivot_chains.sh` | pivot | 4-hop chains, per-hop commands/proxy/rportfwd, stress tests |

## Build Stages

The `Dockerfile` is multi-stage:

1. **builder** — Rust 1.85, compiles `server`, `builder`, and `client` binaries
2. **unit-test** — Runs `cargo test --lib --tests`; fails the build on failure
3. **agents** — Builds test agent binaries using the compiled builder
4. **server** — Debian slim runtime with server + certs + panel
5. **agent** — Minimal Debian slim that runs a pre-built agent binary

## Adding Tests

Create `scripts/test_NN_name.sh`. Source `lib.sh` for helpers:

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

suite "My feature works"
RESP=$(api_get "/api/my-endpoint")
assert_http "returns 200" "200"
assert_contains "has expected field" "my_value" "$RESP"
```

Available helpers: `api_get`, `api_post`, `api_delete`, `login_as`, `wait_agents`, `assert_eq`, `assert_ne`, `assert_contains`, `assert_http`, `skip`, `suite`.

To classify your test, add its name to the appropriate tier in `run_tests.sh`:
- `SMOKE_TESTS` — API-only, no agents needed
- `AGENT_TESTS` — needs connected agents
- `PIVOT_TESTS` — needs pivot chain infrastructure

## Pinned Toolchain

The Dockerfile uses `rust:1.85-bookworm`. The committed `Cargo.lock` pins all transitive dependencies. To update:

1. Bump the Rust version in the `FROM` line
2. Run `cargo update` locally
3. Commit the new `Cargo.lock`

## Cleanup

```bash
docker compose down -v   # removes volumes too
```
