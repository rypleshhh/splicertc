<#
Full-tunnel VPN mode: one-shot route setup for the Windows client.
Run this AFTER client.exe -mode vpn is already connected. Safe to
re-run — it tears down any routes/address left over from a previous
run before re-adding them, so a stale "already exists" from a leftover
route (e.g. after the TUN adapter got recreated) won't block it.

Edit the variables below if the VPS IP, dorm gateway, or tunnel subnet
change.
#>

$ErrorActionPreference = "Continue"

$ServerIP   = "168.222.192.132"
$GatewayIP  = "10.255.164.1"     # dorm Wi-Fi's own default gateway (from ipconfig)
$TunName    = "dormvpn0"
$TunIP      = "10.66.0.2"
$TunMask    = "255.255.255.0"
$TunGateway = "10.66.0.1"
$DNS        = "1.1.1.1"

Write-Host "Waiting for adapter '$TunName'..."
$idx = $null
for ($i = 0; $i -lt 20; $i++) {
    $adapter = Get-NetAdapter -InterfaceAlias $TunName -ErrorAction SilentlyContinue
    if ($adapter) { $idx = $adapter.ifIndex; break }
    Start-Sleep -Milliseconds 500
}
if (-not $idx) {
    Write-Error "Adapter '$TunName' not found after 10s — is 'client.exe -mode vpn' running?"
    exit 1
}
Write-Host "$TunName ifIndex = $idx"

# --- clean slate: remove anything left over from a previous run ---
route delete $ServerIP     2>&1 | Out-Null
route delete 0.0.0.0       2>&1 | Out-Null

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
