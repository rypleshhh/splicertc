<#
One-window launcher for vpn mode: builds the client, starts it, waits
for the TUN adapter, and runs the routing setup — all from a single
Administrator PowerShell window instead of juggling two.

Usage:
  .\run-vpn.ps1                    # build + run using client-config.json
  .\run-vpn.ps1 -Config other.json # use a different config file
  .\run-vpn.ps1 -NoBuild           # skip the `go build` step

Ctrl+C stops the client (it shares this console, so the same Ctrl+C
reaches it). client.exe exiting normally destroys the dormvpn0 adapter,
and Windows removes routes bound to a destroyed adapter on its own — the
only thing that can be left behind is the anti-loop host route to the
server, which is harmless (still points at your real gateway) and gets
cleaned up automatically the next time this script runs (see
setup-vpn-route.ps1's own idempotent "clean slate" step).
#>

param(
    [string]$Config = "client-config.json",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

# --- 0. must be Administrator: the TUN adapter and route changes both need it ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run this from an Administrator PowerShell (TUN + route changes need it)."
    exit 1
}

if (-not (Test-Path $Config)) {
    Write-Error "Config file '$Config' not found — copy client-config.example.json to $Config and fill it in first."
    exit 1
}

# --- 1. build ---
if (-not $NoBuild) {
    Write-Host "Building client.exe..." -ForegroundColor Cyan
    go build -o client.exe .\cmd\client
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed — fix the error above before running."
        exit 1
    }
}

# --- 2. stop any stale client.exe from a previous run, so we don't end
#        up with two TUN adapters/connections fighting each other ---
$stale = Get-Process client -ErrorAction SilentlyContinue
if ($stale) {
    Write-Host "Stopping previous client.exe (PID $($stale.Id -join ', '))..." -ForegroundColor Yellow
    $stale | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# --- 3. start the client, sharing this console (-NoNewWindow) so its
#        log output appears right here instead of a second window ---
Write-Host "`nStarting client.exe -config $Config ...`n" -ForegroundColor Cyan
$client = Start-Process -FilePath ".\client.exe" -ArgumentList @("-config", $Config) -NoNewWindow -PassThru

# --- 4. run the existing, already-tested routing setup once the
#        adapter is up (it does its own wait/retry internally) ---
Start-Sleep -Seconds 2
if (Test-Path .\setup-vpn-route.ps1) {
    & .\setup-vpn-route.ps1
} else {
    Write-Host "setup-vpn-route.ps1 not found — skipping automatic routing; the client is running but nothing is routed through it yet." -ForegroundColor Yellow
}

Write-Host "`n--- VPN running. Ctrl+C to stop. ---`n" -ForegroundColor Green

# --- 5. block here so the window stays open and shows client.exe's
#        live log output until it exits (normally via Ctrl+C) ---
Wait-Process -Id $client.Id -ErrorAction SilentlyContinue
Write-Host "`nclient.exe exited." -ForegroundColor Yellow
