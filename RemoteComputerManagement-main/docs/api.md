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

## Operators (admin only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/operators` | List all operators |
| POST | `/api/operators` | Create operator `{username, password, role}` |
| DELETE | `/api/operators/:id` | Delete operator |
| GET | `/api/audit` | Get audit log (last 200 entries) |

## Listeners

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/listeners` | List all listeners with runtime status |
| POST | `/api/listeners` | Create + start `{name, port, transport, profile_json?}` |
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

## Reverse Port Forwards

| Method | Path | Body | Description |
|--------|------|------|-------------|
| GET | `/api/rportfwds` | — | List all active reverse port forwards |
| POST | `/api/hosts/:id/rportfwd` | `{"bind_port": N, "target_host": "h", "target_port": N}` | Start rportfwd: bind port N on server, tunnel through agent to host:port |
| DELETE | `/api/hosts/:id/rportfwd` | `{"bind_port": N}` | Stop reverse port forward by bind port |

## Task Queue (Hibernation)

The task queue is the command channel for hibernation-mode agents. Commands queued here are claimed in batches on each agent check-in instead of being pushed over a live connection.

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/api/hosts/:id/queue` | `{"command": "whoami"}` | Enqueue a command. Returns `{task_id, command, status: "pending"}`. Returns 201. |
| GET | `/api/hosts/:id/tasks` | — | List all tasks for a session (pending, claimed, completed, failed, cancelled). |
| GET | `/api/hosts/:id/tasks/:task_id` | — | Get a single task including output and error. |
| DELETE | `/api/hosts/:id/tasks/:task_id` | — | Cancel a pending task. Returns 204. Already-claimed tasks cannot be cancelled. |

**Task lifecycle:**
```
pending → claimed (agent checks in) → completed | failed
pending → cancelled (operator deletes before check-in)
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
| GET | `/api/topology/snapshot` | — | Full cross-session interface map: routes, shared subnets, and conflicts across all connected sessions. |

**Plan response:**
```json
{
  "target": "10.10.5.0/24",
  "rendered": "✔  Session #3 (agent-tls)  via eth0  10.10.5.22/24  [score 85]\n   Session #1 (agent-http) via eth1  10.10.0.5/24  [score 42]",
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

## Modules

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/modules` | List available Rhai modules |
| POST | `/api/hosts/:id/modules/:name` | Execute module on session |
| POST | `/api/hosts/:id/extensions/:filename` | Deploy extension file |
| POST | `/api/broadcast/module` | Execute module on all sessions |

## Configuration (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/config/webhook` | Get webhook URL |
| POST | `/api/config/webhook` | Set webhook `{url}` |
| GET | `/api/config/recon` | List auto-recon commands |
| POST | `/api/config/recon` | Add command `{command}` |
| DELETE | `/api/config/recon/:id` | Remove command |
