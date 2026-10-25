<#
One-window launcher for vpn mode: builds the client, starts it, waits
until it has connected, and runs the routing setup, all from a single
Administrator PowerShell window.

Usage:
  .\run-vpn.ps1                    # build + run using client-config.json
  .\run-vpn.ps1 -Config other.json # use a different config file
  .\run-vpn.ps1 -NoBuild           # skip the `go build` step

The client key comes from client_key in the config, or from the
SPLICERTC_CLIENT_KEY environment variable (it wins over the config, and
client.exe inherits it from this window). The tray app doesn't keep the
key in client-config.json, so with a config written by the tray set the
variable first.

The route script gets the server IP from the client's own log line
"connected to vpn channel <IP>:<port>", so the anti-loop route is for
exactly the address the client uses (resolving vpn_addr here could give
a different address). For that the client's log (stderr) goes to a temp
file that this window prints as it grows.

Ctrl+C stops the client (it shares this console, so the same Ctrl+C
reaches it). client.exe exiting destroys the TUN adapter, and Windows
removes routes bound to it on its own. The anti-loop host route to the
server can stay behind; it is harmless (still points at your real
gateway) and the route script removes it on its next run.
#>

param(
    [string]$Config = "client-config.json",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

$routeScript = Join-Path $PSScriptRoot "cmd\tray\setup-vpn-route.ps1"
$clientExe = Join-Path (Get-Location).Path "client.exe"

# --- 0. must be Administrator: the TUN adapter and route changes both need it ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run this from an Administrator PowerShell (TUN + route changes need it)."
    exit 1
}

if (-not (Test-Path $Config)) {
    Write-Error "Config file '$Config' not found, copy client-config.example.json to $Config and fill it in first."
    exit 1
}
if (-not (Test-Path $routeScript)) {
    Write-Error "$routeScript not found."
    exit 1
}

# --- 1. TUN parameters for the route script, computed like client.exe
#        does: client is .2 and gateway .1 of vpn_subnet ---
$cfg = Get-Content $Config -Raw | ConvertFrom-Json
$tunName = if ($cfg.vpn_tun_name) { $cfg.vpn_tun_name } else { "dormvpn0" }
$subnet = if ($cfg.vpn_subnet) { $cfg.vpn_subnet } else { "10.66.0.0/24" }
$netPart, $bitsPart = $subnet.Split("/")
$prefix = [int]$bitsPart
if ($prefix -lt 1 -or $prefix -gt 30) {
    Write-Error "vpn_subnet '$subnet': need an IPv4 subnet of /30 or bigger."
    exit 1
}
$bytes = ([ipaddress]$netPart).GetAddressBytes()
[Array]::Reverse($bytes)
$mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
$network = [BitConverter]::ToUInt32($bytes, 0) -band $mask
function ConvertTo-IP([uint32]$v) {
    $b = [BitConverter]::GetBytes($v)
    [Array]::Reverse($b)
    ([ipaddress]$b).ToString()
}
$tunArgs = @{
    TunName         = $tunName
    TunIP           = ConvertTo-IP ($network + 2)
    TunGateway      = ConvertTo-IP ($network + 1)
    TunPrefixLength = $prefix
}

# --- 2. build ---
if (-not $NoBuild) {
    Write-Host "Building client.exe..." -ForegroundColor Cyan
    go build -o client.exe .\cmd\client
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed, fix the error above before running."
        exit 1
    }
}

# --- 3. stop a stale client.exe from a previous run (only this very
#        exe, not anything else that happens to be called "client") ---
$stale = Get-Process client -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $clientExe }
if ($stale) {
    Write-Host "Stopping previous client.exe (PID $($stale.Id -join ', '))..." -ForegroundColor Yellow
    $stale | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# --- 4. start the client in this console; its log goes to a file that
#        is printed below ---
$logFile = Join-Path $env:TEMP "splicertc-client-$PID.log"
Write-Host "`nStarting client.exe -config $Config ...`n" -ForegroundColor Cyan
$client = Start-Process -FilePath $clientExe -ArgumentList @("-config", $Config) -NoNewWindow -PassThru `
    -RedirectStandardError $logFile

$reader = $null
$routed = $false
try {
    # --- 5. print the log; on the first "connected" line set up routes ---
    while ($true) {
        if (-not $reader -and (Test-Path $logFile)) {
            $fs = [IO.File]::Open($logFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = New-Object IO.StreamReader($fs)
        }
        if ($reader) {
            while ($null -ne ($line = $reader.ReadLine())) {
                Write-Host $line
                if (-not $routed -and $line -match 'connected to vpn channel (\d{1,3}(?:\.\d{1,3}){3}):\d+') {
                    $routed = $true
                    & $routeScript -ServerIP $Matches[1] @tunArgs
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "Routing setup failed, stopping the client." -ForegroundColor Red
                        Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
                        exit 1
                    }
                    Write-Host "`n--- VPN running. Ctrl+C to stop. ---`n" -ForegroundColor Green
                }
            }
        }
        if ($client.HasExited) { break }
        Start-Sleep -Milliseconds 200
    }
} finally {
    # also on Ctrl+C: don't leave IPv6 blocked after the tunnel is gone
    & $routeScript -Teardown
    if ($reader) { $reader.Close() }
    Remove-Item $logFile -ErrorAction SilentlyContinue
}
Write-Host "`nclient.exe exited." -ForegroundColor Yellow
