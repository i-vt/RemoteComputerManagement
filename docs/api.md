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
