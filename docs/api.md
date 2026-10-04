# API Reference

Base URL: `http://127.0.0.1:8080`

All authenticated endpoints require `X-API-KEY: <key>` header.

## Authentication

### POST /api/auth/login
Login with username/password, receive API key.

```json
// Request
{"username": "admin", "password": "..."}

// Response 200
{"api_key": "uuid", "username": "admin", "role": "admin"}
```

### GET /api/auth/me
Returns current operator info.

### POST /api/auth/logout
Invalidates the calling operator's current API key (the `operator_sessions` row is removed).

### POST /api/auth/change_password
Change your own password. Body: `{"current_password, new_password}`. Existing keys other than the caller's are revoked.

## Operators (admin only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/operators` | List all operators |
| POST | `/api/operators` | Create operator `{username, password, role}` |
| DELETE | `/api/operators/:name` | Delete operator |
| POST | `/api/operators/:name/revoke` | Revoke all of an operator's API keys (forces re-login) |
| POST | `/api/operators/:name/password` | Admin password reset `{password}` |
| GET | `/api/audit` | Get audit log (last 200 entries) |

API keys are two-tier: `operators` holds the account and role, and every login
mints a row in `operator_sessions` (one key per session). Revoke and logout
operate on the session tier, so deleting one key does not disturb other live
sessions of the same operator.

## Listeners

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/listeners` | List all listeners with runtime status |
| POST | `/api/listeners` | Create + start `{name, port, transport, profile_json?}` |
| GET | `/api/listeners/profiles` | List the malleable traffic profiles available in `traffic_profiles/` (requires execute role) |
| POST | `/api/listeners/:id/start` | Start a stopped listener |
| POST | `/api/listeners/:id/stop` | Stop a running listener |
| DELETE | `/api/listeners/:id` | Stop + delete (admin only) |

## Sessions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/hosts` | List all active sessions |
| POST | `/api/hosts/:id/command` | Send command `{command: "whoami"}` |
| GET | `/api/hosts/:id/output/:req_id` | Poll for command output |
| POST | `/api/broadcast` | Send command to all sessions |
| POST | `/api/broadcast/module` | Run a server-side module once per active session `{module_name, args?}` (see Modules) |
| POST | `/api/hosts/:id/upload` | Upload one file chunk to the agent `{path, batch_ts, chunk_idx, total_chunks, data_b64}` - the server forwards these as `file:write_chunk` commands |
| GET | `/api/hosts/:id/screenshots` | List screenshots captured from this session |
| GET | `/api/hosts/:id/files/browse?path=/` | Browse remote filesystem |
| GET | `/api/hosts/:id/history` | Session command history |
| GET | `/api/history` | Global command history |

## Session Notes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/hosts/:id/notes` | Get notes and tags |
| POST | `/api/hosts/:id/notes` | Add note `{note, tag?}` |
| DELETE | `/api/hosts/:id/notes/:note_id` | Delete note |

## Proxies

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/proxies` | List active SOCKS proxies |
| POST | `/api/hosts/:id/proxy` | Start SOCKS proxy |
| DELETE | `/api/hosts/:id/proxy` | Stop SOCKS proxy |
| POST | `/api/hosts/:id/proxy/check` | Check the egress IP seen through the session's proxy tunnel |

## Reverse Port Forwards

| Method | Path | Body | Description |
|--------|------|------|-------------|
| GET | `/api/rportfwds` | - | List all active reverse port forwards |
| POST | `/api/hosts/:id/rportfwd` | `{"bind_port": N, "target_host": "h", "target_port": N}` | Start rportfwd: bind port N on server, tunnel through agent to host:port |
| DELETE | `/api/hosts/:id/rportfwd` | `{"bind_port": N}` | Stop reverse port forward by bind port |

## Task Queue (Hibernation)

The task queue is the command channel for hibernation-mode agents. Commands queued here are claimed in batches on each agent check-in instead of being pushed over a live connection.

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/api/hosts/:id/queue` | `{"command": "whoami"}` | Enqueue a command. Returns `{task_id, command, status: "pending"}`. Returns 201. |
| GET | `/api/hosts/:id/tasks` | - | List all tasks for a session (pending, claimed, completed, failed, cancelled). |
| GET | `/api/hosts/:id/tasks/:task_id` | - | Get a single task including output and error. |
| DELETE | `/api/hosts/:id/tasks/:task_id` | - | Cancel a pending task. Returns 204. Already-claimed tasks cannot be cancelled. |

**Task lifecycle:**
```
pending -> claimed (agent checks in) -> completed | failed
pending -> cancelled (operator deletes before check-in)
```

**Polling for results:**
```bash
TASK=$(curl -sX POST -H "X-API-KEY: $KEY" \
  -d '{"command":"id"}' http://server:8080/api/hosts/3/queue)
TASK_ID=$(echo "$TASK" | jq -r '.task_id')

# Poll until status is no longer "pending" or "claimed"
while true; do
  STATUS=$(curl -s -H "X-API-KEY: $KEY" \
    http://server:8080/api/hosts/3/tasks/$TASK_ID | jq -r '.status')
  [ "$STATUS" = "completed" ] && break
  sleep 5
done
curl -s -H "X-API-KEY: $KEY" \
  http://server:8080/api/hosts/3/tasks/$TASK_ID | jq '.output'
```

## Topology

Passive pivot-path planning based on network interfaces reported by agents at registration. No traffic is sent to agents.

| Method | Path | Query | Description |
|--------|------|-------|-------------|
| GET | `/api/topology/plan` | `?target=<ip_or_cidr>` | Rank sessions as pivot candidates toward `target`. Returns candidates with scores and a rendered text plan. 400 if target is not a valid IPv4 address or CIDR. |
| GET | `/api/topology/snapshot` | - | Full cross-session interface map: routes, shared subnets, and conflicts across all connected sessions. |

**Plan response:**
```json
{
  "target": "10.10.5.0/24",
  "rendered": "✔  Session #3 (agent-tls) via eth0 10.10.5.22/24 [score 85]\n Session #1 (agent-http) via eth1 10.10.0.5/24 [score 42]",
  "candidates": [
    {
      "session_id": 3,
      "hostname": "agent-tls",
      "interface": "eth0",
      "address": "10.10.5.22/24",
      "score": 85
    }
  ]
}
```

Scoring factors (higher = better candidate):

| Factor | Points |
|--------|--------|
| More specific prefix (e.g. /24 vs /16) | +prefix_len |
| Physical ethernet (`eth`, `en`) | +20 |
| Wireless (`wlan`, `wlp`) | +10 |
| RFC-1918 private address | +5 |
| Docker/bridge/virtual interface | −10 |
| Interface not UP | −50 |
| Interface not RUNNING | −30 |

## Modules and Extensions

Modules are server-side scripts (`modules/`); the server runs `run(session_id)`
once per target session. Extensions are agent-side scripts (`extensions/`);
deploying one pushes an `ext:load` command to the agent. See
[Extensions](extensions.md) for the binding sets.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/modules` | List available Rhai modules |
| GET | `/api/modules/:name` | Read module source |
| PUT | `/api/modules/:name` | Create or overwrite a module `{content}` |
| DELETE | `/api/modules/:name` | Delete a module |
| POST | `/api/hosts/:id/modules/:name` | Execute module server-side for one session `{args?}`; returns `{result, output}` |
| POST | `/api/broadcast/module` | Execute module server-side once per active session |
| GET | `/api/extensions` | List available extensions |
| GET | `/api/extensions/:name` | Read extension source |
| PUT | `/api/extensions/:name` | Create or overwrite an extension `{content}` |
| DELETE | `/api/extensions/:name` | Delete an extension |
| POST | `/api/hosts/:id/extensions/:filename` | Deploy extension to an agent `{args?}` |

## Builder

Runs the same `builder` binary the CLI uses, server-side, as a tracked job.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/builder/build` | Start a build job. Body mirrors the CLI flags (see below). Returns `{job_id}` |
| GET | `/api/builder/jobs` | List build jobs with status |
| GET | `/api/builder/jobs/:id/status` | Poll one job: `{status, log, artifact_name, download_url, started_at, finished_at}` |
| GET | `/api/builder/jobs/:id/download` | Download the finished artifact |

`BuildRequest` fields (all optional except `host` and `port`; defaults match
the CLI): `platform` (`linux`, `linux-musl`, `windows`, `macos`),
`transport` (`tls`, `tcp-plain`, `named-pipe`, `http`, `https`), `profile`,
`format` (`exe`, `dll`, `service`, `stager`, `shellcode`, `donut`,
`pe_to_shellcode`, `pic_c`, `bin`), `sleep`, `jitter_min`, `jitter_max`,
`bloat`, `debug`, `days`, `sni_override`, `alpn_protocols`,
`hibernation_mode`, `batch_size`, `sleep_mask` (`none`, `ekko`,
`spoofed-stack`), `indirect_syscalls`, `stack_spoof`, `patch_amsi_etw`,
`heap_encrypt`, `guard_domain`, `guard_hostname`, `guard_hour_start`,
`guard_hour_end`, `guard_no_system`, `valid_parents`, `proxy_url`,
`proxy_user`, `proxy_pass`, `auto_pivot_port`, `sc_hash`, `sc_userdata`,
`sc_flags`, `sc_output`, `pic_src` (inline C source for `pic_c`), `pipeline`
(e.g. `pe,donut`), `name`, `icon`, `icon_preset`, `certs_dir`, and the signing
group `sign`, `sign_cert`, `sign_pass`, `sign_ts`, `sign_name`, `sign_url`,
`sign_cn`, `allow_vm`.

## IOCs

Every persistence install, dropped file, and extension action can register an
indicator so cleanup is auditable.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/iocs` | List all IOCs across sessions |
| GET | `/api/hosts/:id/iocs` | List IOCs for one session |
| POST | `/api/hosts/:id/iocs` | Add an IOC `{ioc_type, path, detail?, cleanup_cmd?}` |
| POST | `/api/iocs/:id/clean` | Mark an IOC cleaned |
| DELETE | `/api/iocs/:id` | Delete an IOC record |

## Loot and Downloads

Exfiltrated material lands under `downloads/` as per-target RCM packages.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/loot` | List loot files across all packages |
| DELETE | `/api/loot?path=<subpath>` | Delete a loot entry (operator/admin) |
| GET | `/api/loot/zip` | Stream an entire loot folder as ZIP (ZIP64, constant memory) |
| GET | `/api/downloads/*path` | Download a single file from `downloads/` |

## RCM Packages (chain of custody)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/rcm/packages` | List packages with seal status |
| POST | `/api/rcm/seal` | Seal a package `{name}`: writes the SHA-256 manifest generation (operator/admin) |
| POST | `/api/rcm/verify` | Verify a sealed package `{name}` against its manifest |

## Hosted Payload Links

Builder jobs can publish their artifact behind an unauthenticated,
benign-named URL for target-side retrieval:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dl/:token/:name` | Download a hosted payload. Links are random-tokened, persisted, and pruned on a schedule; no API key required |

This is separate from the stager endpoint `/stage/<build_id>` on the HTTP C2
listener, which is HMAC-authenticated with the per-build challenge key (see
[Builder Guide](builder.md#stager)).

## Configuration (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/config/webhook` | Get webhook URL |
| POST | `/api/config/webhook` | Set webhook `{url}` |
| GET | `/api/config/recon` | List auto-recon commands |
| POST | `/api/config/recon` | Add command `{command}` |
| DELETE | `/api/config/recon/:id` | Remove command |