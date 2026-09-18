RU [Русский](README.md) | EN **English**

# splicertc

A from-scratch TCP/TLS tunnel that carries traffic through a network
that blocks non-standard ports. Two ways to use it: a full VPN
(`vpn` mode, all IP traffic) and a specialized channel for game UDP
with droppable-frame logic and multipath duplication to minimize the
latency/loss cost of running datagrams over TCP (`tun` mode).

## Components

- **server** (`cmd/server`) — runs on the VPS. Channels: reliable
  (SOCKS5-style, `:8443`), droppable (framed, TTL-dropped, `:8444`),
  glue (real captured UDP from a TUN, `:8446`), vpn (full IP tunnel with
  server-side NAT, `:8447` by default — in practice usually moved to
  whatever port actually gets through the network's filtering, see
  "Quick start").
- **client** (`cmd/client`) — runs on the gaming/work machine. Modes:
  `vpn` (all traffic through the tunnel, optionally with selective
  multipath for games), `socks5` (local proxy), `tun` (game UDP
  capture, optionally multipath), `droptest` (synthetic loss testing).
- **gencert** (`cmd/gencert`) — throwaway self-signed dev certs.
- **tunprobe** (`cmd/tunprobe`) — diagnostic: shows what a TUN sees.
- **portprobe** (`cmd/portprobe`) — network diagnostic: which ports
  actually get through the filtering, before and independent of the
  tunnel (see "Picking a port" below).

Everything is driven by **config files** — `server-config.json` on the
server, `client-config.json` on the client. Command-line flags exist
only as a one-off override for a single value, not as the primary way
to run anything.

## Quick start

### 1. Secret

```
openssl rand -base64 32
```

Copy the output — this string goes into the `"psk"` field **on both
server and client**, verbatim, identical.

### 2. Server

```
cp server-config.example.json server-config.json
```

Open `server-config.json`, fill in `psk`. The example is already set to
port `587` for `vpn_addr` — a port that works for a typical filtered
network (see the next section if you want to check/pick a different
one), and it doesn't conflict with 443, which often already has another
service on it (e.g. Xray). The `10.66.0.0/24` subnet can stay as-is.
Open the port in the VPS firewall if it has one (`ufw allow 587/tcp`) —
otherwise the server comes up but is unreachable from outside. Then:

```
docker compose up --build -d
docker compose logs -f
```

`docker-compose.yml` mounts `server-config.json` into the container and
runs the binary with zero flags — the whole run is: edit the file, bring
up the container. The file has to exist BEFORE the first run (otherwise
Docker creates an empty directory in its place instead of mounting a
file — the `cp` above is exactly for that).

Needs a Linux host with `net.ipv4.ip_forward` enabled (once, on the
host itself, not in the container):

```
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-dormtun.conf
```

### 3. Client

```
cp client-config.example.json client-config.json
```

Open `client-config.json`, fill in `vpn_addr` (your server's IP, port
`587`, matching the server example) and the same `psk`. Needs
`wintun.dll` next to `client.exe` (https://www.wintun.net/, already in
the repo) and an **Administrator** shell.

Recommended way to launch — one script that builds the client, starts
it, and sets up routing, all in a single window:

```powershell
.\run-vpn.ps1
```

It builds `client.exe`, stops a stale process from a previous run (if
any), starts the client in the same window (log output visible right
away), waits for the TUN interface to come up, and sets up routing
itself — including verifying via ipify that traffic actually goes
through the tunnel. `Ctrl+C` stops it. Flags: `-Config path.json`
(different config), `-NoBuild` (skip rebuilding).

Manual way (two windows, if you need more control — see "`vpn` mode"
below for exactly what `run-vpn.ps1` does under the hood):
```
go build -o client.exe .\cmd\client
.\client.exe
```

### One-off flag override

Any config field can be overridden by a flag of the same name for a
single run, without editing the file:

```
.\client.exe -mode socks5 -listen 127.0.0.1:1080
```

Flag names match config field names (see the tables below). A different
config path: `-config path/to/file.json`.

## Picking a port: `cmd/portprobe`

Filtered networks usually let through only a small set of standard
ports, and that set can change over time — don't assume port 587 (or
any other) will keep working forever. `portprobe` is a standalone
diagnostic tool: the server listens on a batch of TCP/UDP ports at once
and replies with a token containing the port number (to tell "this port
is genuinely open" apart from "something else answered instead" — e.g.
a transparent proxy); the client probes the list and prints what got
through.

Build (cross-compiling for the Linux VPS works right from Windows):
```powershell
go build -o portprobe.exe .\cmd\portprobe
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o portprobe-linux .\cmd\portprobe
$env:GOOS=""; $env:GOARCH=""
```

**On the VPS** (foreground — don't leave it running in the background on
a production box, it's a diagnostic, not a service):
```bash
scp portprobe-linux root@<SERVER_IP>:~/portprobe   # from Windows
chmod +x portprobe
./portprobe -mode server -tcp 1-999 -udp none
```
Port ranges are given as `1-999` or a list `80,443,993`. The server
automatically skips ports already in use (e.g. 22 for sshd, 443 for
Xray) — it never steals a port from a live service. The firewall for the
tested ports needs to be opened separately (`ufw allow ...`) — otherwise
you're measuring your own firewall, not the network.

**From the client** (on the network you're testing):
```powershell
.\portprobe.exe -mode client -host <SERVER_IP> -tcp 1-999 -udp none -parallel 200 -timeout 2s
```

Additionally:
- `-sustain 5m` — after the scan, hold each port that opened under
  traffic for 5 minutes: connecting briefly and dropping right away is
  useless for a tunnel, and `portprobe` checks that separately.
- `-targets default` (or your own `host:port,host:port` list) — check
  reachability of known public services (Google, GitHub, Gmail SMTP,
  etc.) **with no server of your own and no firewall changes needed** —
  a fast way to see which ports aren't blocked by the network at all,
  before opening anything on your own VPS.

## Reference: config fields

### `server-config.json`

| Field | Flag | Default | What it does |
|---|---|---|---|
| `addr` | `-addr` | `:8443` | reliable channel address (SOCKS5-style) |
| `drop_addr` | `-drop-addr` | `:8444` | droppable channel address |
| `glue_addr` | `-glue-addr` | `:8446` | glue channel address (real UDP) |
| `vpn_addr` | `-vpn-addr` | `:8447` | full-tunnel VPN channel address |
| `vpn_tun_name` | `-vpn-tun-name` | `dormvpn0` | server-side TUN interface name |
| `vpn_tun_mtu` | `-vpn-tun-mtu` | `1400` | server-side TUN MTU |
| `vpn_subnet` | `-vpn-subnet` | `10.66.0.0/24` | private VPN subnet (server = `.1`, client = `.2`) |
| `egress_iface` | `-egress-iface` | auto-detect | interface to MASQUERADE internet egress out of |
| `cert` / `key` | `-cert` / `-key` | `devcerts/dev.crt` / `dev.key` | TLS certificate |
| `psk_file` | `-psk-file` | empty (auth disabled) | path to a file holding the secret |
| `psk` | — | empty | the secret written directly into the config (simpler than `psk_file`) |

### `client-config.json`

| Field | Flag | Default | What it does |
|---|---|---|---|
| `mode` | `-mode` | `socks5` | `socks5` \| `droptest` \| `tun` \| `vpn` |
| `listen` | `-listen` | `127.0.0.1:1080` | local SOCKS5 port (`socks5`) |
| `server` | `-server` | `127.0.0.1:8443` | reliable channel address (`socks5`) |
| `drop_addr` | `-drop-addr` | `127.0.0.1:8444` | droppable channel address (`droptest`) |
| `glue_addr` | `-glue-addr` | `127.0.0.1:8446` | glue channel address (`tun`) |
| `tun_name` | `-tun-name` | `dormtun0` | TUN interface name (`tun`) |
| `tun_mtu` | `-tun-mtu` | `1420` | TUN MTU (`tun`) |
| `tun_paths` | `-tun-paths` | `1` | number of parallel duplicated paths / multipath (`tun`) |
| `tun_measure` | `-tun-measure` | `false` | send measurement pings (`tun`) |
| `tun_measure_interval` | `-tun-measure-interval` | `33ms` | ping spacing (`tun`) |
| `vpn_addr` | `-vpn-addr` | `127.0.0.1:8447` | vpn channel address (`vpn`) |
| `vpn_tun_name` | `-vpn-tun-name` | `dormvpn0` | TUN interface name (`vpn`) |
| `vpn_tun_mtu` | `-vpn-tun-mtu` | `1400` | TUN MTU (`vpn`) |
| `game_processes` | `-game-processes` | empty | comma-separated executable names — their UDP traffic rides glue+multipath instead of the single `vpn` stream (`vpn`) |
| `game_paths` | `-game-paths` | `3` if `game_processes` is set | number of parallel paths for classified game UDP (`vpn`) |
| `drop_count` | `-drop-count` | `0` | number of frames in the stress test (`droptest`) |
| `drop_interval` | `-drop-interval` | `33ms` | spacing between frames (`droptest`) |
| `drop_paths` | `-drop-paths` | `1` | number of parallel paths (`droptest`) |
| `insecure` | `-insecure` | `false` | skip the server's TLS certificate verification |
| `server_pin` | `-server-pin` | empty | SHA-256 (hex) of the server's certificate — if set, the server must present exactly this certificate |
| `psk_file` | `-psk-file` | empty | path to a file holding the secret |
| `psk` | — | empty | the secret written directly into the config |

`server-config.json`/`client-config.json` are gitignored — never commit
the real files once they hold a live secret; only `*.example.json`
(placeholder values) live in the repo.

**On `insecure` vs `server_pin`**: without `server_pin`, `insecure: true`
accepts ANY certificate from anyone — a TLS-intercepting middlebox on
the network can present its own certificate and read all traffic in the
clear, and the PSK check won't catch it (it just passes straight
through to the real server via the interceptor). The server prints its
fingerprint at startup (`cert fingerprint (put this in the client's
server_pin to enable pinning): ...`) — copy that line into the client's
`server_pin`, and `insecure` stops being a hole: the server must present
exactly that certificate, which can't be forged without its private key
even under TLS 1.3.

## `vpn` mode: all traffic through the tunnel

A full replacement for your normal internet connection: the client
creates a TUN, captures ALL IP traffic (not just UDP), the server
writes it into its own TUN and NATs it out through the Linux kernel
(iptables MASQUERADE).

`client-config.json`:
```json
{
  "mode": "vpn",
  "vpn_addr": "<SERVER_IP>:587",
  "vpn_tun_name": "dormvpn0",
  "vpn_tun_mtu": 1400,
  "insecure": true,
  "psk": "<secret>"
}
```

### Launching and routing

Easiest: `.\run-vpn.ps1` (Administrator shell) — builds the client,
starts it, waits for the TUN interface to come up, and sets up the
routing below itself, all in one window. The rest of this section is
what the script does automatically — only needed if you want more
control or something went wrong and you're fixing it by hand.

Running the client directly: `.\client.exe` (Administrator shell), wait
for `connected to vpn channel ...`. Then — routing, in a SECOND
Administrator shell:

```
# 1. Find your current gateway (ipconfig, "Default Gateway") and the server's IP.

# 2. Anti-loop route — MANDATORY before overriding the default route,
#    otherwise the client's own connection to the server loops back
#    into itself.
route add <SERVER_IP> mask 255.255.255.255 <GATEWAY_IP> metric 1

# 3. Address the interface + a public DNS (your network's own DNS
#    becomes unreachable the moment the default route changes).
netsh interface ip set address name="dormvpn0" static 10.66.0.2 255.255.255.0
netsh interface ip set dns name="dormvpn0" static 1.1.1.1

# 4. Override the default route.
route add 0.0.0.0 mask 0.0.0.0 10.66.0.1 metric 1
```

If `route add 0.0.0.0 ...` bound to the wrong interface (`route print
-4` shows interface `10.255.164.241` instead of `10.66.0.2`) —
recreate it with an explicit interface index:
```
$idx = (Get-NetAdapter -InterfaceAlias "dormvpn0").ifIndex
route delete 0.0.0.0 mask 0.0.0.0 10.66.0.1
route add 0.0.0.0 mask 0.0.0.0 10.66.0.1 metric 1 if $idx
```

Undo (restore normal internet):
```
route delete 0.0.0.0 mask 0.0.0.0 10.66.0.1
route delete <SERVER_IP> mask 255.255.255.255 <GATEWAY_IP>
```
then `Ctrl+C` the client.

Verify: `ping 1.1.1.1`, `curl https://example.com`,
`curl -UseBasicParsing https://api.ipify.org` (should return the
server's IP, not your own).

### Selective multipath for games (optional)

By default all traffic rides one TCP stream — under a burst of small
packets (e.g. a rapid sequence of in-game actions) that's exposed to TCP
head-of-line blocking: one lost packet holds up everything behind it.
To give specific processes multipath duplication (several parallel
paths, first one wins — the same mechanism `tun` mode uses), list them
in `game_processes`:

```json
{
  "mode": "vpn",
  "vpn_addr": "<SERVER_IP>:587",
  "glue_addr": "<SERVER_IP>:993",
  "game_processes": ["deadlock.exe"],
  "game_paths": 3,
  "psk": "<secret>"
}
```

The client figures out which process owns each UDP port itself (via the
Windows IP Helper API, `GetExtendedUdpTable` — no third-party
dependency), so there's no need to guess game-server IP ranges. UDP
only; that process's TCP and everything else still rides the single
`vpn` stream. The server also needs a working `glue_addr` in
`server-config.json` for this — no server code changes, just both
channels listening (two different ports).

#### Finding the exact process name

Classification matches the exe filename **with its extension**
(`deadlock.exe`, not `deadlock`) — the client checks against the actual
owner of the UDP socket, not a fuzzy name search, so it needs to be
exact, `.exe` included.

**Task Manager** (`Ctrl+Shift+Esc`) → "Details" tab, while the game is
running — the exact name is right there in the "Name" column.

**PowerShell**, while the game is running — list every process with a
visible window (easiest way to spot the game among everything else):
```powershell
Get-Process | Where-Object { $_.MainWindowTitle -ne "" } | Select-Object ProcessName, Path
```
Or by a substring if you roughly know the name already:
```powershell
Get-Process -Name "*deadlock*" | Select-Object ProcessName, Path
```
PowerShell's `ProcessName` column has **no** `.exe` (it strips it) —
add the extension yourself in the config. `Path` shows the full
executable path, which settles the exact filename unambiguously.

To confirm classification is actually working: with `client.exe`
running and `game_processes` set, watch `docker compose logs -f` on the
server — the first packet it sees from the game produces a
`glue: new flow ... -> ...` line for that destination, which never
happens for anything else (that traffic rides the `vpn` channel
silently).

## Authentication

Without `psk` in the config (or `-psk-file`), the server accepts
connections from anyone who finds its IP:port — an open proxy and an
open UDP/IP relay. `psk` is the preferred way (see the field tables
above); `psk_file`/`-psk-file` is the older form, a path to a separate
file:

```
openssl rand -base64 32 > dormtun.key
chmod 600 dormtun.key
```

Same file's contents on both ends — copy it over, don't retype it (the
key is SHA-256'd internally, so whitespace differences don't matter,
but the actual passphrase must match exactly). Don't pass the secret as
a bare flag value like `-psk some-secret` — the command line is visible
to any local user via `/proc/<pid>/cmdline`.

The glue channel additionally refuses to relay to loopback, link-local,
and multicast destinations, and to a handful of UDP amplification-vector
ports (DNS, NTP, memcached, SSDP, etc.) regardless of who's asking —
defense in depth even for an authenticated client's mistakes.

## First-time setup: dev certs

```
go run ./cmd/gencert
```

Writes `devcerts/dev.crt`/`dev.key` — a throwaway self-signed pair for
localhost (the server config's default `cert`/`key` point here).
`insecure: true` on the client skips verification of that certificate —
fine for a personal tunnel to a server you control by IP, not a
substitute for real certificate pinning.

## `socks5` mode: local proxy

The project's original mode: the client opens a local SOCKS5 proxy, the
server forwards whatever gets requested through it. TCP-only (no SOCKS5
UDP ASSOCIATE) — not suitable for games, but needs no
Administrator/TUN.

`client-config.json`:
```json
{
  "mode": "socks5",
  "listen": "127.0.0.1:1080",
  "server": "<SERVER_IP>:8443",
  "insecure": true,
  "psk": "<secret>"
}
```

```
.\client.exe
```

Point any SOCKS5-compatible application (browser, curl, etc.) at
`127.0.0.1:1080`.

## `tun` mode: game UDP, measurement, and multipath

Captures only real UDP traffic (not general internet) through the glue
channel, with optional duplication across multiple paths.

`client-config.json`:
```json
{
  "mode": "tun",
  "glue_addr": "<SERVER_IP>:8446",
  "tun_name": "dormtun0",
  "tun_mtu": 1420,
  "tun_paths": 1,
  "tun_measure": true,
  "tun_measure_interval": "33ms",
  "insecure": true,
  "psk": "<secret>"
}
```

`.\client.exe` — prints a rolling summary every 5 seconds: RTT
(min/mean/p95/max), jitter, loss, for the client<->server leg only.
Let it run 30+ seconds, `Ctrl+C`, change `tun_paths` to `3` in the
config, rerun — same network, same server, comparing loss/jitter
between the two runs is the actual answer to "does multipath help on my
real connection." No TUN route or running game needed — the pings are
generated by the client itself.

To actually route a game server through the TUN (not just measure):
```
netsh interface ip set address name="dormtun0" static 10.99.0.1 255.255.255.0
route add <GAME_SERVER_IP> mask 255.255.255.255 10.99.0.1
```

**Don't route the tunnel server itself through the TUN** (`route add
<SERVER_IP> ... dormtun0`) — the client's own connection to the server
would get sent back into the TUN it's serving, a loop. Only route real
game-server destinations.

## Diagnosing what a TUN interface sees

`tunprobe` is a standalone binary, no tunnel involved, doesn't use a
config (a one-off diagnostic — flags make more sense here):

```
go build -o tunprobe.exe ./cmd/tunprobe
.\tunprobe.exe -name dormtun0 -mtu 1420
```

Shows what's flowing and how it's classified (real traffic vs. local
discovery noise like mDNS/SSDP/NetBIOS) — useful to check before wiring
a new interface into anything.

## Testing loss behavior (Linux, no game needed)

`droptest` sends synthetic frames; pair with `tc netem` on the server's
loopback to inject real loss.

`client-config.json`:
```json
{
  "mode": "droptest",
  "drop_addr": "<SERVER_IP>:8444",
  "drop_count": 300,
  "drop_interval": "33ms",
  "drop_paths": 3,
  "insecure": true,
  "psk": "<secret>"
}
```

```
sudo tc qdisc add dev lo root netem loss 20% delay 40ms 15ms
./client
sudo tc qdisc del dev lo root
```

`insecure: true` skips TLS cert verification — dev/testing only.
