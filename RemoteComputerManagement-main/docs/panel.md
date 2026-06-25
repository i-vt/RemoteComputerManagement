# Panel Guide

## Pages

| # | Page | Description |
|---|------|-------------|
| 1 | **Dashboard** | Session count, OS distribution chart, connection status |
| 2 | **Network** | Cytoscape.js graph of sessions and pivot relationships |
| 3 | **Control** | Host table with action buttons |
| 4 | **Files** | Remote file browser per session |
| 5 | **Proxies** | Active SOCKS5 proxy tunnels |
| 6 | **Tasks** | Module execution queue |
| 7 | **History** | Global command history with output |
| 8 | **Listeners** | Listener management + auto-recon config |
| 9 | **Jobs** | Background job status across all sessions |
| 0 | **Audit** | Operator audit log (who did what) |

## Host Action Buttons

Each session row has:
- **Proxy** — start/stop SOCKS5 tunnel
- **Beacon** — toggle fast mode (pulsing red bolt when active)
- **Shell** — open interactive terminal modal
- **Processes** — view process list with inject buttons
- **Screenshot** — capture and view all monitors
- **Notes** — add tags and notes to the session

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1`-`9`, `0` | Navigate to page by number |
| `Esc` | Close any open modal |
| `Ctrl+K` | Focus the terminal input |
| `T` | Toggle dark/light theme |
| `R` | Refresh host list |
| `?` | Show shortcut help toast |

## Notifications

- **Toast system** — slide-in cards (top-right) for events
- **New session alert** — green toast + audio ping when a session checks in
- **Webhook** — POST to Slack/Discord on new sessions (configure via Listeners page or `POST /api/config/webhook`)

## Theming

Press `T` or click the sun/moon icon in the sidebar. Light mode applies to the main content area only (sidebar stays dark). Persisted in localStorage.

## Login

The panel authenticates with username + password. On success, the API key is stored in localStorage for subsequent requests. The sidebar shows the operator name and role (color-coded: red=admin, green=operator, gray=viewer).
