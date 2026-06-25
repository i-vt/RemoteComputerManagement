# tests/docker/scripts/windows-entrypoint.ps1
# Waits for the cross-compiled Windows agent binary on the shared volume,
# then runs it. Mirrors the Linux agent-entrypoint.sh behavior.

$ErrorActionPreference = "Stop"

$transport = if ($env:AGENT_TRANSPORT) { $env:AGENT_TRANSPORT } else { "tls" }
$name      = if ($env:AGENT_NAME)      { $env:AGENT_NAME }      else { "unknown" }
$binary    = "C:\shared\agent-${transport}.exe"

Write-Host "[agent:${name}] Waiting for agent binary at ${binary}..."

$found = $false
for ($i = 1; $i -le 120; $i++) {
    if (Test-Path $binary) {
        Write-Host "[agent:${name}] Binary found, starting..."
        $found = $true
        break
    }
    Start-Sleep -Seconds 1
}

if (-not $found) {
    Write-Host "[agent:${name}] FATAL: agent binary never appeared after 120s"
    exit 1
}

# Run the agent — exec equivalent in PowerShell
& $binary
exit $LASTEXITCODE
