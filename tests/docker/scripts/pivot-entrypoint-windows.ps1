# tests/docker/scripts/pivot-entrypoint-windows.ps1
#
# Windows counterpart of pivot-entrypoint.sh. Waits for the chain-specific
# agent binary named by PIVOT_BINARY on the shared volume, waits
# PIVOT_DELAY seconds for the parent pivot listener to come up, then runs
# the binary. Mounted as C:\entrypoint.ps1 by the pivot-win services in
# docker-compose.pivot.yml.

$ErrorActionPreference = "Stop"

$binary = "C:\shared\" + $(if ($env:PIVOT_BINARY) { $env:PIVOT_BINARY } else { "agent-tls.exe" })
$name   = if ($env:AGENT_NAME) { $env:AGENT_NAME } else { "pivot-unknown" }
$delay  = if ($env:PIVOT_DELAY) { [int]$env:PIVOT_DELAY } else { 0 }

Write-Host "[pivot:$name] Waiting for binary $binary..."

$found = $false
for ($i = 1; $i -le 180; $i++) {
    if (Test-Path $binary) {
        Write-Host "[pivot:$name] Binary found. Waiting ${delay}s for parent pivot listener..."
        if ($delay -gt 0) { Start-Sleep -Seconds $delay }
        Write-Host "[pivot:$name] Starting..."
        $found = $true
        break
    }
    Start-Sleep -Seconds 1
}

if (-not $found) {
    Write-Host "[pivot:$name] FATAL: binary never appeared after 180s"
    exit 1
}

& $binary
exit $LASTEXITCODE
