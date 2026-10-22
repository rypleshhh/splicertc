<#
Full-tunnel VPN mode: one-shot route setup for the Windows client.
Run this AFTER client.exe (-mode vpn) is already connected. Safe to
re-run — tears down any routes/address left over from a previous run
(e.g. after the TUN adapter got recreated) before re-adding them, and
auto-detects the dorm gateway instead of needing it typed in by hand.

The server IP comes from -ServerIP (the tray app passes it), otherwise
from vpn_addr in client-config.json next to this script.

The tunnel is IPv4 only. While it's up, a firewall rule blocks global
IPv6 (2000::/3), otherwise IPv6 traffic would go around the tunnel.
Apps fall back to IPv4. "-Teardown" removes the rule again (the tray
does that on disconnect); the routes go away with the TUN adapter.
#>

param(
    [string]$ServerIP = "",
    [switch]$Teardown
)

$ErrorActionPreference = "Continue"

$FwRule = "splicertc: block IPv6 outside the tunnel"

if ($Teardown) {
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    Write-Host "IPv6 block removed."
    exit 0
}

if (-not $ServerIP) {
    $cfgPath = Join-Path $PSScriptRoot "client-config.json"
    if (-not (Test-Path $cfgPath)) {
        Write-Error "No -ServerIP given and $cfgPath not found."
        exit 1
    }
    $vpnAddr = (Get-Content $cfgPath -Raw | ConvertFrom-Json).vpn_addr
    $hostPart = ($vpnAddr -replace ':\d+$', '')
    $ServerIP = [System.Net.Dns]::GetHostAddresses($hostPart) |
        Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
        Select-Object -First 1 | ForEach-Object { $_.IPAddressToString }
    if (-not $ServerIP) {
        Write-Error "Could not resolve the server address '$vpnAddr' from $cfgPath."
        exit 1
    }
}
Write-Host "Server IP: $ServerIP"

$TunName    = "dormvpn0"
$TunIP      = "10.66.0.2"
$TunMask    = "255.255.255.0"
$TunGateway = "10.66.0.1"
$DNS        = "1.1.1.1"

# --- auto-detect the real (non-VPN) default gateway, before we touch
#     any routing ---
$gwRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -ne $TunName -and $_.NextHop -ne "0.0.0.0" } |
    Sort-Object RouteMetric |
    Select-Object -First 1
if (-not $gwRoute) {
    Write-Error "Could not auto-detect the current default gateway — check 'ipconfig' / 'Get-NetRoute' manually and hardcode `$GatewayIP` in this script."
    exit 1
}
$GatewayIP = $gwRoute.NextHop
Write-Host "Detected real gateway: $GatewayIP (via $($gwRoute.InterfaceAlias))"

Write-Host "Waiting for adapter '$TunName'..."
$idx = $null
for ($i = 0; $i -lt 20; $i++) {
    $adapter = Get-NetAdapter -InterfaceAlias $TunName -ErrorAction SilentlyContinue
    if ($adapter) { $idx = $adapter.ifIndex; break }
    Start-Sleep -Milliseconds 500
}
if (-not $idx) {
    Write-Error "Adapter '$TunName' not found after 10s — is 'client.exe' (-mode vpn) running?"
    exit 1
}
Write-Host "$TunName ifIndex = $idx"

# --- clean slate: remove anything left over from a PREVIOUS run of
#     THIS script only. Deliberately scoped to the exact gateway we
#     ourselves add below ($TunGateway) — a bare "route delete 0.0.0.0"
#     with no gateway matches (and removes) every default route on the
#     system, including the real one, which is exactly what took the
#     whole connection down last time this ran on a machine with no
#     leftover tunnel route to begin with.
route delete $ServerIP     2>&1 | Out-Null
route delete 0.0.0.0 mask 0.0.0.0 $TunGateway 2>&1 | Out-Null

# --- address + DNS ---
netsh interface ip set address name="$TunName" static $TunIP $TunMask | Out-Null
netsh interface ip set dns name="$TunName" static $DNS | Out-Null

# --- anti-loop route: the tunnel's own TCP connection must keep using
#     the real gateway, not get captured by the default route we're
#     about to add ---
route add $ServerIP mask 255.255.255.255 $GatewayIP metric 1 | Out-Null

# --- default route through the tunnel, pinned to the TUN adapter by
#     index so Windows can't misattribute it to another interface ---
route add 0.0.0.0 mask 0.0.0.0 $TunGateway metric 1 if $idx | Out-Null

# --- lowest interface metric for the TUN: Windows asks the DNS servers
#     of interfaces in metric order, so 1.1.1.1 on the TUN goes first
#     instead of the dorm DNS ---
Set-NetIPInterface -InterfaceIndex $idx -InterfaceMetric 1 -ErrorAction SilentlyContinue

# --- block global IPv6 while the tunnel is up (IPv4-only tunnel, IPv6
#     would leak around it). Link-local IPv6 is not touched. ---
Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $FwRule -Direction Outbound -Action Block `
    -RemoteAddress "2000::/3" -Profile Any | Out-Null
Write-Host "IPv6 outside the tunnel: blocked (firewall rule '$FwRule')"

Write-Host "`nDefault routes now:"
route print -4 | Select-String "^\s+0\.0\.0\.0"

Write-Host "`nVerifying egress IP (should be $ServerIP)..."
try {
    $ip = (Invoke-WebRequest -UseBasicParsing -Uri "https://api.ipify.org" -TimeoutSec 10).Content
    Write-Host "Egress IP: $ip"
    if ($ip -eq $ServerIP) {
        Write-Host "OK — traffic is going through the tunnel." -ForegroundColor Green
    } else {
        Write-Host "MISMATCH — traffic is NOT going through the tunnel." -ForegroundColor Red
    }
} catch {
    Write-Host "Could not verify egress IP: $_" -ForegroundColor Yellow
}

Write-Host "`nTo undo (restore normal internet):" -ForegroundColor Cyan
Write-Host "  route delete 0.0.0.0 mask 0.0.0.0 $TunGateway"
Write-Host "  route delete $ServerIP mask 255.255.255.255 $GatewayIP"
Write-Host "  .\setup-vpn-route.ps1 -Teardown   (removes the IPv6 block)"
