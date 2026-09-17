<#
Full-tunnel VPN mode: one-shot route setup for the Windows client.
Run this AFTER client.exe (-mode vpn) is already connected. Safe to
re-run — tears down any routes/address left over from a previous run
(e.g. after the TUN adapter got recreated) before re-adding them, and
auto-detects the dorm gateway instead of needing it typed in by hand.

Edit the variables below if the VPS IP/port or tunnel subnet change.
#>

$ErrorActionPreference = "Continue"

$ServerIP   = "82.23.163.204"
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
