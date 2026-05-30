# Operator Guide

## Login

Open the panel, enter the server URL and your credentials. The admin creates operator accounts via **Audit Log** page or API.

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

### 4. Deploy
Execute the agent on the target. When it checks in, you'll see a green toast notification and the session appears in the host table.

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

## OPSEC Tips
- Use `bg <command>` for long-running commands so they don't block
- Use `secure_delete` to clean up dropped files
- Use `timestomp` to match file timestamps to nearby system files
- Set a kill date on agents (`--days 30`) so they don't persist forever
- Use HTTPS transport with a malleable profile that mimics legitimate traffic
- Check `evasion:syscall_check` to verify syscall numbers resolved correctly before injection
