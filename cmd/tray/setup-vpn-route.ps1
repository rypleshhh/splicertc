<#
Full-tunnel VPN mode: route setup for the Windows client. Run it AFTER
client.exe (-mode vpn) has connected. tray.exe has this script built in
and runs it from memory (a copy on disk next to an elevated exe could be
swapped by any program). run-vpn.ps1 runs this file directly.

-ServerIP is the IP client.exe actually connected to (it logs
"connected to vpn channel <IP>:<port>"). The tunnel's own connection is
kept on the real gateway with a host route to it.

The -Tun* parameters must match vpn_tun_name and vpn_subnet in
client-config.json (client is .2, gateway .1 of the subnet).

Safe to re-run: leftovers of a previous run are removed first. Any
failure exits with code 1, nothing is reported as working when it isn't.

The tunnel is IPv4 only. While it's up, a firewall rule blocks global
IPv6 (2000::/3), otherwise IPv6 traffic would go around the tunnel.
"-Teardown" removes the rule again; the routes go away with the TUN
adapter.
#>

[CmdletBinding(DefaultParameterSetName = "Setup")]
param(
    [Parameter(Mandatory, ParameterSetName = "Setup")]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$ServerIP,
    [Parameter(ParameterSetName = "Setup")]
    [string]$TunName = "dormvpn0",
    [Parameter(ParameterSetName = "Setup")]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$TunIP = "10.66.0.2",
    [Parameter(ParameterSetName = "Setup")]
    [ValidateRange(1, 30)]
    [int]$TunPrefixLength = 24,
    [Parameter(ParameterSetName = "Setup")]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$TunGateway = "10.66.0.1",
    [Parameter(ParameterSetName = "Setup")]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$DNS = "1.1.1.1",
    [Parameter(Mandatory, ParameterSetName = "Teardown")]
    [switch]$Teardown
)

# Errors stop the script (the Net* cmdlets are module functions that
# ignore this preference, so they also get -ErrorAction Stop); native
# tools are checked by exit code.
$ErrorActionPreference = "Stop"

$FwRule = "splicertc: block IPv6 outside the tunnel"

function Fail([string]$Message) {
    Write-Host "ERROR: $Message"
    exit 1
}

if ($Teardown) {
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    Write-Host "IPv6 block removed."
    exit 0
}

try {
    Write-Host "Server IP: $ServerIP"

    # real (non-VPN) default gateway, found before we touch any routing
    $gwRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -ne $TunName -and $_.NextHop -ne "0.0.0.0" } |
        Sort-Object RouteMetric |
        Select-Object -First 1
    if (-not $gwRoute) {
        Fail "could not find the current default gateway (check 'Get-NetRoute -DestinationPrefix 0.0.0.0/0')"
    }
    $GatewayIP = $gwRoute.NextHop
    Write-Host "Real gateway: $GatewayIP (via $($gwRoute.InterfaceAlias))"

    Write-Host "Waiting for adapter '$TunName'..."
    $idx = $null
    for ($i = 0; $i -lt 20; $i++) {
        $adapter = Get-NetAdapter -InterfaceAlias $TunName -ErrorAction SilentlyContinue
        if ($adapter) { $idx = $adapter.ifIndex; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $idx) {
        Fail "adapter '$TunName' not found after 10s, is client.exe (-mode vpn) running?"
    }
    Write-Host "$TunName ifIndex = $idx"

    # Leftovers of a previous run of THIS script only. The default route
    # delete names our gateway: a bare "route delete 0.0.0.0" removes every
    # default route, the real one too. Failures here just mean "nothing
    # to remove".
    route delete $ServerIP | Out-Null
    route delete 0.0.0.0 mask 0.0.0.0 $TunGateway | Out-Null

    # netsh wants a dotted mask
    $bits = ("1" * $TunPrefixLength).PadRight(32, "0")
    $TunMask = (0..3 | ForEach-Object { [Convert]::ToByte($bits.Substring($_ * 8, 8), 2) }) -join "."

    netsh interface ip set address name="$TunName" static $TunIP $TunMask
    if ($LASTEXITCODE -ne 0) { Fail "netsh set address $TunIP/$TunPrefixLength on $TunName failed" }
    netsh interface ip set dns name="$TunName" static $DNS
    if ($LASTEXITCODE -ne 0) { Fail "netsh set dns $DNS on $TunName failed" }

    # anti-loop route: the tunnel's own TCP connection must keep using the
    # real gateway, not the default route added below
    route add $ServerIP mask 255.255.255.255 $GatewayIP metric 1 if $gwRoute.ifIndex
    if ($LASTEXITCODE -ne 0) { Fail "route add $ServerIP via $GatewayIP failed" }

    # default route through the tunnel, pinned to the TUN by index
    route add 0.0.0.0 mask 0.0.0.0 $TunGateway metric 1 if $idx
    if ($LASTEXITCODE -ne 0) { Fail "route add 0.0.0.0/0 via $TunGateway failed" }

    # Windows asks DNS servers in interface metric order, so the lowest
    # metric makes the TUN's DNS go first instead of the dorm's
    Set-NetIPInterface -InterfaceIndex $idx -InterfaceMetric 1 -ErrorAction Stop

    # block global IPv6 while the tunnel is up (link-local is not touched)
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $FwRule -Direction Outbound -Action Block `
        -RemoteAddress "2000::/3" -Profile Any -ErrorAction Stop | Out-Null
    Write-Host "IPv6 outside the tunnel: blocked (firewall rule '$FwRule')"

    # Local check instead of asking an outside service: internet traffic
    # must pick the TUN, the server itself must not.
    $probeIf = @(Find-NetRoute -RemoteIPAddress "1.1.1.1" -ErrorAction Stop | Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($probeIf.Count -ne 1 -or $probeIf[0] -ne $idx) {
        Fail "traffic to 1.1.1.1 does not go through $TunName (ifIndex $($probeIf -join ',') instead of $idx)"
    }
    $serverIf = @(Find-NetRoute -RemoteIPAddress $ServerIP -ErrorAction Stop | Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($serverIf -contains $idx) {
        Fail "the route to the server $ServerIP goes into the tunnel itself"
    }
    Write-Host "OK: internet traffic goes through $TunName, the server via $($gwRoute.InterfaceAlias)."
} catch {
    Fail "$_"
}
