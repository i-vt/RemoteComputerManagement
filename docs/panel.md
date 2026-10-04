# Panel Guide

The panel is served by the API server at `http://127.0.0.1:8080/` - do not
open `panel/index.html` as a file, its relative fetches only resolve when
served by the server.

## Pages

16 pages in the sidebar (the **Users** entry is hidden for non-admin roles):

| Page | Description |
|------|-------------|
| **Dashboard** | Session count, OS distribution chart, connection status |
| **Network Map** | Cytoscape.js graph of sessions and pivot relationships, with a collapsible **Topology planner** panel (plan toward an IP/CIDR + cross-session snapshot). Node action menu includes a Screenshot capture shortcut |
| **Sessions** | Host table with action buttons and host detail view |
| **Files** | Remote file browser per session |
| **Loot** | RCM package browser over `downloads/` with streaming ZIP download, plus the **RCM packages** card (seal/verify chain-of-custody actions) |
| **Users** | Operator account management (admin only) |
| **Proxies** | Active SOCKS5 proxy tunnels plus the **Reverse Port Forwards** card (start/stop rportfwd per session) |
| **Broadcast** | Send a command or a server-side module to all sessions |
| **Listeners** | Listener management, auto-recon config, and the **New-Session Webhook** card (admin only) |
| **Builder** | Build agents from the panel: all core fields plus advanced options - guardrails (domain/hostname/hours/no-system, valid_parents), Authenticode signing group, hibernation/batch size, sleep mask and evasion toggles, `allow_vm`, platform incl. linux-musl, formats incl. donut/pe_to_shellcode/pic_c/bin pipelines, icon/VERSIONINFO customization. Egress proxy (`--proxy-*`) is CLI-only for now |
| **Scripts** | Extension/module manager: browse, create, edit, delete, and deploy |
| **History** | Global command history with output |
| **Jobs** | Background job status across all sessions |
| **Task Queue** | Pending/claimed/completed hibernation tasks per session, with cancel |
| **Audit Log** | Operator audit log (who did what) |
| **Artifacts** | IOC tracker: indicators registered by persistence installs, drops, and extensions, with clean marking |

## Host Action Buttons

Each session row has:
- **Proxy** - start/stop SOCKS5 tunnel
- **Beacon** - toggle fast mode (pulsing red bolt when active)
- **Shell** - open interactive terminal modal
- **Processes** - view process list with inject buttons
- **Screenshot** - capture and view all monitors
- **Notes** - add tags and notes to the session

## Keyboard Shortcuts

Defined in `panel/js/shortcuts.js`:

| Key | Action |
|-----|--------|
| `1`-`9` | Navigate: 1 Dashboard, 2 Network Map, 3 Sessions, 4 Files, 5 Proxies, 6 Broadcast, 7 History, 8 Listeners, 9 Jobs. There is no `0` binding; the remaining pages are mouse/mobile-nav only |
| `Esc` | Close any open modal (terminal, processes, loot preview, file manager, screenshot view, notes) |
| `Ctrl+K` | Focus the terminal input (if a terminal is open; otherwise shows a hint toast) |
| `T` | Toggle dark/light theme |
| `R` | Refresh host list |
| `?` | Show shortcut help toast |

## Notifications

- **Toast system** - slide-in cards (top-right) for events
- **New session alert** - green toast + audio ping when a session checks in
- **Webhook** - POST to Slack/Discord on new sessions. Configure it from the
  webhook card on the **Listeners** page (admin only) or via
  `POST /api/config/webhook`

## Theming

Press `T` or click the sun/moon icon in the sidebar. Light mode applies to the main content area only (sidebar stays dark). Persisted in localStorage.

## Login

The panel authenticates with username + password. On success, the API key is stored in localStorage for subsequent requests. The sidebar shows the operator name and role (color-coded: red=admin, green=operator, gray=viewer).
