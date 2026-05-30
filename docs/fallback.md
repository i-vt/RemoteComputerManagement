# Fallback Profiles

Fallback endpoints let the agent try multiple C2 addresses when the primary is unreachable. Each endpoint can have its own transport, malleable profile, and proxy settings.

## Configuration

Pass a fallback JSON file to the builder:
```bash
cargo run --bin builder -- \
  --host primary.com --port 443 --transport https \
  --fallback-file fallback_profiles/staged_infrastructure.json
```

## Strategies

| Strategy | Behavior |
|----------|----------|
| `priority` | Try lowest priority number first; fall to next on failure |
| `round_robin` | Cycle through endpoints in order, skip dead |
| `random` | Weighted random selection across alive endpoints |
| `failover` | Use first until dead, permanently switch to next |

## Endpoint Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | — | C2 hostname or IP |
| `port` | number | — | C2 port |
| `transport` | string | `tls` | `tls`, `tcp_plain`, `http`, `https`, `named_pipe` |
| `profile` | object | — | Per-endpoint malleable profile override |
| `proxy` | object | — | Per-endpoint proxy override |
| `priority` | number | `0` | Lower = tried first (priority/failover) |
| `weight` | number | `1` | Higher = more likely (random) |
| `max_failures` | number | `5` | Mark dead after N consecutive failures |

## Dead Endpoint Handling

When an endpoint accumulates `max_failures` consecutive failures, it's marked dead for `dead_time_secs` (default 300). During this window, the manager skips it. After the dead time expires, it's retried. If all endpoints are dead simultaneously, all are reset.

## Pre-Built Templates

| File | Scenario |
|------|----------|
| `simple_failover.json` | Two servers, primary + backup |
| `multi_cloud_round_robin.json` | Spread across AWS/Azure/GCP |
| `redirector_chain.json` | Fast redirector + slow CDN fallback |
| `corporate_proxy.json` | HTTPS through corp proxy + direct TLS backup |
| `mixed_transport.json` | HTTPS → TLS → named pipe cascade |
| `weighted_random.json` | 60/30/10 weighted distribution |
| `staged_infrastructure.json` | Short-haul (disposable) + long-haul (persistent) |

See `fallback_profiles/` for full JSON examples.
