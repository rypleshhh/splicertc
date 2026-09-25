RU [Русский](README.md) | EN **English**

# splicertc

A from-scratch TCP/TLS tunnel that carries traffic through a network
that blocks non-standard ports. Two ways to use it: a full VPN
(`vpn` mode, all IP traffic) and a specialized channel for game UDP
with droppable-frame logic and multipath duplication to minimize the
latency/loss cost of running datagrams over TCP (`tun` mode).

## Contents

- [Components](#components)
- [Quick start](#quick-start)
- [`vpn` mode: all traffic through the tunnel](#vpn-mode-all-traffic-through-the-tunnel)
- [Windows app: `cmd/tray`](#windows-app-cmdtray)
- [Authentication](#authentication)
- [Other client modes](#other-client-modes)
- [Diagnostics](#diagnostics)
- [Reference: config fields](#reference-config-fields)

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
- **tray** (`cmd/tray`) — minimal Windows app on top of `vpn` mode: a
  config-editing window + tray icon.
- **genkey** (`cmd/genkey`) — generates an Ed25519 key for client
  authentication.
- **gencert** (`cmd/gencert`) — throwaway self-signed dev certs.
- **portprobe** (`cmd/portprobe`) — network diagnostic: which ports
  actually get through the filtering, before and independent of the
  tunnel.
- **tunprobe** (`cmd/tunprobe`) — diagnostic: shows what a TUN sees.

Everything is driven by **config files** — `server-config.json` on the
server, `client-config.json` on the client. Command-line flags exist
only as a one-off override for a single value, not as the primary way
to run anything.

## Quick start

### 1. Key

```
go run ./cmd/genkey -name "me"
```

Prints two lines: `public_key` (for the server) and `client_key` (for
the client) — an Ed25519 keypair, not a shared password. The public
part isn't secret; never show the private one to anyone but the client
it was generated for. Want to give a friend access? Run the command
again with their name (`-name friend1`) and you get them their own
separate pair; revoking one person later is deleting their one line
from `authorized_keys.json` on the server — nobody else needs to change
anything. More detail in ["Authentication"](#authentication) below.

### 2. Server

```
cp server-config.example.json server-config.json
cp authorized_keys.example.json authorized_keys.json
```

The certificate — generate it once (locally, where Go is already needed
to build `client.exe`) and copy it to the server, into the same
directory as `docker-compose.yml`:
```
go run ./cmd/gencert
scp -r devcerts root@<SERVER_IP>:~/splicertc/
```

In `authorized_keys.json`, add the `public_key` from step 1 (one entry
per person you're granting access to). `server-config.json` can stay
as-is — the example is already set to port `587` for `vpn_addr` — a
port that works for a typical filtered network (see
["Diagnostics"](#diagnostics) if you want to check/pick a different
one), and it doesn't conflict with 443, which often already has another
service on it (e.g. Xray). The `10.66.0.0/24` subnet can stay as-is.
Open the port in the VPS firewall if it has one (`ufw allow
587/tcp`) — otherwise the server comes up but is unreachable from
outside. Then:

```
docker compose up --build -d
docker compose logs -f
```

`docker-compose.yml` mounts `server-config.json`, `authorized_keys.json`,
and `devcerts/` into the container and runs the binary with zero flags —
the whole run is: edit the files, bring up the container. All three have
to exist BEFORE the first run (otherwise Docker creates an empty
directory in their place instead of mounting a file — the commands above
are exactly for that). Mounting `devcerts/` isn't a formality: without
it, every image rebuild bakes a fresh certificate, and you'd have to dig
through `docker compose logs` for a new fingerprint for every client
again; `go run ./cmd/gencert` is a one-time step and never needs
touching again (see the [`pin_file`](#checking-the-server-is-real-insecure-pin_file-server_pin)
section for why this matters).

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
`587`, matching the server example) and `client_key` from step 1 (the
same pair whose `public_key` is already in the server's
`authorized_keys.json`). The example's `pin_file` field is already set
up — on first connect the client remembers the server's certificate
itself and checks against it from then on, no need to go digging
through `docker compose logs` for a fingerprint. Needs `wintun.dll`
next to `client.exe` (https://www.wintun.net/, already in the repo) and
an **Administrator** shell.

The most convenient way to launch is [`cmd/tray`](#windows-app-cmdtray):
a tray icon, "Connect"/"Disconnect" with the mouse, no console and no
scripts to run by hand.

A no-GUI but still one-command way — a script that builds the client,
starts it, and sets up routing, all in a single window:

```powershell
.\run-vpn.ps1
```

It builds `client.exe`, stops a stale process from a previous run (if
any), starts the client in the same window (log output visible right
away), waits for the TUN interface to come up, and sets up routing
itself — including verifying via ipify that traffic actually goes
through the tunnel. `Ctrl+C` stops it. Flags: `-Config path.json`
(different config), `-NoBuild` (skip rebuilding).

Manual way (two windows, if you need more control — see
["`vpn` mode"](#vpn-mode-all-traffic-through-the-tunnel) below for
exactly what `run-vpn.ps1` does under the hood):
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

Flag names match config field names (see
["Reference: config fields"](#reference-config-fields)). A different
config path: `-config path/to/file.json`.

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
  "client_key": "<client_key from cmd/genkey>"
}
```

### Launching and routing

Easiest: `.\run-vpn.ps1` (Administrator shell) or
[`cmd/tray`](#windows-app-cmdtray) — both build/start the client, wait
for the TUN interface to come up, and set up the routing below
themselves, no manual steps. The rest of this section is what both do
automatically — only needed if you want more control or something went
wrong and you're fixing it by hand.

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

### Latency under load

All non-game traffic rides inside one TCP connection, and TCP has one
queue for everything. Left alone, a download (Steam, a browser, Windows
Update) fills the socket buffer and the router buffer on the slowest
hop (the dorm network) with megabytes of data — and every game, voice
or DNS packet waits behind it; that's where ping spikes come from. What
the tunnel does about it (all on by default, nothing to configure):

- **Fair queueing inside the tunnel (FQ-CoDel)** — packets are sorted
  per flow; a flow that just woke up (a game tick, a voice frame, a DNS
  query, a TCP ACK) goes out ahead of one that's been downloading for a
  while, and a flow that keeps a queue standing for more than a few
  milliseconds gets a packet dropped — the signal for its TCP to slow
  down. The same algorithm OpenWrt/Linux use against bufferbloat,
  running in both directions (client and server).
- **A cap on unsent data in the kernel** (server, `TCP_NOTSENT_LOWAT`
  16 KB) — so "what goes next" is decided by that queue, not by a
  multi-megabyte kernel FIFO. Doesn't affect throughput.
- **BBR on the server** instead of CUBIC — CUBIC speeds up until it
  overflows the router buffer on the path; BBR paces at the real
  bottleneck rate and keeps that buffer nearly empty. Set only on the
  tunnel's own sockets, nothing else on the server (e.g. Xray) is
  affected. If the server log says `transport: BBR unavailable`, run
  `sudo modprobe tcp_bbr` on the host (and add `tcp_bbr` to
  `/etc/modules-load.d/` so it survives a reboot); normally the log
  shows `transport: tunnel sockets use BBR + 16 KB unsent-data cap`.
- **Multipath paths don't wait for each other** — each has its own
  writer; a path stuck in a retransmit no longer delays the copies on
  the others, and stale (>150ms) copies on it just aren't sent. And the
  client no longer waits on the vpn socket before sending a game packet
  into glue.

When the queue is actually cutting something, the server logs
`vpn: queue dropped N packets ...` every 30 seconds — normal during
downloads; that's how it keeps them from inflating latency.

**If ping still spikes during downloads**, the queue is building in the
network's router instead (the tunnel sends faster than the link can
carry). Then turn on a rate cap slightly below the real link speed:
measure it (a speedtest without the tunnel) and set ~85–90% of it —
`vpn_down_mbps` in `server-config.json` (downloads) and, if uploads
hurt too, `vpn_up_mbps` in `client-config.json`. E.g. a 50/20 Mbit/s
link → `"vpn_down_mbps": 44` and `"vpn_up_mbps": 17`. The queue then
forms inside the tunnel, where FQ-CoDel manages it, instead of in the
router, which the tunnel can't reach. Off by default — without knowing
the real link speed it could cut throughput for nothing.

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
  "client_key": "<client_key from cmd/genkey>"
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

## Windows app: `cmd/tray`

A minimal, dark-themed interface on top of `vpn` mode: a miniature
window listing named connections (a server + key per name) instead of
hand-editing JSON, plus a tray icon for "Connect"/"Disconnect" with the
mouse. It doesn't reinvent anything — under the hood it's exactly what
`run-vpn.ps1` already does (starts `client.exe`, waits for the tunnel
to come up, calls `setup-vpn-route.ps1`), just through a window instead
of a console.

Build:
```powershell
go build -ldflags "-H=windowsgui" -o tray.exe .\cmd\tray
```
`-H=windowsgui` — so a console doesn't flash on launch.

`cmd/tray/resource.syso` is already checked into the repo and gets
picked up by the build automatically (standard `go build` behavior,
nothing extra to pass) — it embeds a Windows manifest
(`cmd/tray/tray.manifest`), without which the app crashes on startup
with `create window: TTM_ADDTOOL failed` (needs Common Controls v6,
which the `lxn/walk` GUI library doesn't get without a manifest). No
need to touch `resource.syso` by hand; if it ever needs regenerating
from `tray.manifest`, that's `goversioninfo` (`go install
github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest`, then
`goversioninfo -manifest tray.manifest -skip-versioninfo -o
resource.syso <any-versioninfo.json>` from `cmd/tray`).

`tray.exe` expects the same files next to it as a manual `vpn` mode run
needs: `client.exe`, `setup-vpn-route.ps1`, `wintun.dll`. Neither
`connections.json` nor `client-config.json` needs to exist beforehand —
the window creates both on the first "Save"/"Connect".

Double-clicking `tray.exe` triggers its own UAC prompt if it isn't
already elevated (Administrator is needed for the TUN adapter and
routes). Then:

- **The connection list** — at the top of the window: one row per saved
  name (server), font a bit larger than the rest of the window so rows
  are easier to click and read. Stored in `connections.json` next to
  the exe (see `connections.example.json` — a plain array of `{name,
  vpn_addr, client_key, game_processes}` objects). Double-click a row to
  connect to that server right away. If `connections.json` doesn't
  exist yet but a manually-configured `client-config.json` does (from an
  earlier version of this app, or from "Quick start") — the first run
  turns it into one entry named "По умолчанию" ("Default") instead of
  discarding it.
- **The fields below the list**: name, server address, private key
  (`client_key` from `cmd/genkey`, masked with dots), and a
  comma-separated game process list (optional, see
  ["Selective multipath for games"](#selective-multipath-for-games-optional)).
  Clicking a row fills the fields from it — edit and re-save as needed,
  including renaming (change "Name" and hit "Save" — the old name
  doesn't stick around as a separate leftover entry). "New" clears the
  fields for a fresh entry. "Save" adds/updates the entry and writes
  `connections.json`; "Delete" removes the selected one. "Ping" checks
  right now that the server responds and the key is accepted — a real
  TLS+auth attempt against `vpn_addr` with the fields' current
  `client_key` (not just "is the port open"), without bringing up the
  full tunnel or routing; useful before "Connect", especially after
  editing the fields. The "Connect" button below the fields saves
  first, then connects — same as double-clicking a row, but with
  whatever unsaved edits are currently in the fields.
- **If there are no saved connections yet** — the window opens right
  away; once at least one is saved, the app starts minimized straight
  to the tray, no window on screen.
- **Tray icon**: gray — disconnected, green — connected, red — error.
  Right-click for the menu: "Settings" (open/raise the same window any
  time), "Connect" (reuses whatever `client-config.json` currently has
  from the last connection), "Disconnect", "Open log" (opens `tray.log`
  next to the exe — it logs everything: `client.exe`'s output, the
  routing script's output, status changes), "Quit". The window's own
  close button just hides it back to the tray — only "Quit" actually
  exits the app.
- **Dark theme** — the title bar and every field/button/list are dark
  (via `DwmSetWindowAttribute`/`SetWindowTheme`, the same trick many
  Win32 apps use to look dark on Windows 10/11 without fully custom-
  drawing every control). Not configurable and doesn't follow the
  system theme — just always dark.

**Honest about the limits**: this is a thin wrapper, not a rewritten,
more robust client. If the tunnel drops on its own (`client.exe` still
crashes on any disconnect — see IDEAS.md P1 #4, not fixed yet), the app
notices and shows "client exited unexpectedly," but doesn't reconnect
automatically — you have to click "Connect" again. Treat it as a
convenient control panel on top of the existing stack, not a guarantee
of automatic reconnection.

## Authentication

Without `authorized_keys_file` in the config, the server accepts
connections from anyone who finds its IP:port — an open proxy and an
open UDP/IP relay. There are two independent things going on here:
**who's allowed to connect** (the client proves its identity to the
server) and **is this actually the right server** (the client checks it
hasn't connected to an interceptor).

### Who can connect: Ed25519 and `authorized_keys.json`

Authentication is Ed25519 keys, not a shared password: the server holds
a list of public keys (`authorized_keys.json`, one entry per person),
each client holds its own private key. That means you can tell friends
apart in the logs and revoke one without touching anyone else's access —
delete their line from `authorized_keys.json` and restart the server.

Generate a pair (once per person you're granting access to, including
yourself):
```
go run ./cmd/genkey -name "friend1"
```
It prints `public_key` (paste as a line in the server's
`authorized_keys.json`) and `client_key` (paste into that person's
`client_key` config field). The public key isn't secret — send it over
any channel, even a public one. The private one (`client_key`) is a
secret: send it over a channel you trust, never commit it to git
(`client-config.json` and `authorized_keys.json` are already
gitignored; only `*.example.json` lives in the repo).

There's no dedicated command-line flag for the private key itself
(only `-client-key-file <path>`) — the command line is visible to any
local user via `/proc/<pid>/cmdline`, so keep the key in the config
(`client_key`) or a separate file (`client_key_file`) only.

### Checking the server is real: `insecure`, `pin_file`, `server_pin`

Without a pin, `insecure: true` accepts ANY certificate from anyone — a
TLS-intercepting middlebox on the network can present its own
certificate and read all traffic in the clear, and the client-key check
won't catch it (it just passes straight through to the real server via
the interceptor).

**Recommended: `pin_file`** (already set up in the example config). On
the first connection the client accepts whatever certificate the server
presents, saves its fingerprint to that file, and from then on verifies
against it automatically on every future run — the same trust model
ssh's `known_hosts` uses. No server logs to read, ever — provided the
server's certificate doesn't change between connections, which needs
the mounted `devcerts/` from Quick Start step 2 (without it, every
server image rebuild changes the certificate, and `pin_file` would need
resetting after every `docker compose up --build`). If the server's
certificate ever does change (reinstall, manual replacement), delete
the `pin_file` — the next run trusts the first connection again and
re-saves.

**Alternative: manual `server_pin`** — if you want full control (never
auto-trust even the first connection), the server prints its
fingerprint at startup (`cert fingerprint (put this in the client's
server_pin to enable pinning): ...`, visible in `docker compose logs`) —
copy that line into the client's `server_pin` instead of using
`pin_file`. Just as strong, just requires one manual step per
certificate change instead of zero. If both fields are set,
`server_pin` wins.

Either way, the guarantee is the same: the server must present exactly
the remembered/configured certificate, which can't be forged without
its private key even under TLS 1.3.

The certificate itself is a throwaway self-signed pair — `go run
./cmd/gencert` writes `devcerts/dev.crt`/`dev.key` for localhost (the
server config's default `cert`/`key` point here). No certificate
authority signed it, so without pinning it means nothing at all — the
trust comes entirely from pinning above, not from the mere presence of
TLS.

### Brute-force/scan defense

After 3 failed authentication attempts (wrong public key, bad
signature, etc.) from the same IP, the server bans that IP for 10
minutes — new connections from it are refused immediately, without
attempting a handshake. A successful authentication resets the counter.
The ban can't tell a scanner apart from a legitimate client that just
mistyped its own `client_key`, so it stays short and every ban is
logged loudly (`auth: banning <IP> until ...`) — if your own client
suddenly can't connect, the reason is right there in
`docker compose logs`.

### Amplification-attack defense in the glue channel

The glue channel additionally refuses to relay to loopback, link-local,
and multicast destinations, and to a handful of UDP amplification-vector
ports (DNS, NTP, memcached, SSDP, etc.) regardless of who's asking —
defense in depth even for an authenticated client's mistakes.

## Other client modes

Besides the main `vpn` mode, the client has three specialized modes —
for when a full VPN isn't needed, and for testing.

### `socks5`: local proxy

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
  "client_key": "<client_key from cmd/genkey>"
}
```

```
.\client.exe
```

Point any SOCKS5-compatible application (browser, curl, etc.) at
`127.0.0.1:1080`.

### `tun`: game UDP, measurement, and multipath

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
  "client_key": "<client_key from cmd/genkey>"
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

### `droptest`: testing loss behavior (Linux, no game needed)

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
  "client_key": "<client_key from cmd/genkey>"
}
```

```
sudo tc qdisc add dev lo root netem loss 20% delay 40ms 15ms
./client
sudo tc qdisc del dev lo root
```

`insecure: true` skips TLS cert verification — dev/testing only.

## Diagnostics

Two standalone tools, not part of the tunnel itself — both work on
their own, without this project's client-server protocol.

### `portprobe`: picking a port

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

### `tunprobe`: what a TUN interface sees

A standalone binary, no tunnel involved, doesn't use a config (a
one-off diagnostic — flags make more sense here):

```
go build -o tunprobe.exe ./cmd/tunprobe
.\tunprobe.exe -name dormtun0 -mtu 1420
```

Shows what's flowing and how it's classified (real traffic vs. local
discovery noise like mDNS/SSDP/NetBIOS) — useful to check before wiring
a new interface into anything.

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
| `authorized_keys_file` | `-authorized-keys-file` | empty (auth disabled) | path to `authorized_keys.json` — the list of public keys allowed to connect |
| `vpn_down_mbps` | `-vpn-down-mbps` | `0` (no cap) | cap the server→client rate in Mbit/s, slightly below the real download speed (see "Latency under load") |

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
| `vpn_up_mbps` | `-vpn-up-mbps` | `0` (no cap) | cap the client→server rate in Mbit/s, slightly below the real upload speed (`vpn`, see "Latency under load") |
| `drop_count` | `-drop-count` | `0` | number of frames in the stress test (`droptest`) |
| `drop_interval` | `-drop-interval` | `33ms` | spacing between frames (`droptest`) |
| `drop_paths` | `-drop-paths` | `1` | number of parallel paths (`droptest`) |
| `insecure` | `-insecure` | `false` | skip the server's TLS certificate verification |
| `server_pin` | `-server-pin` | empty | SHA-256 (hex) of the server's certificate — if set, the server must present exactly this certificate |
| `pin_file` | `-pin-file` | empty | path to a file that auto-saves the pin on first connect (trust-on-first-use), an alternative to manually copying `server_pin` — ignored if `server_pin` is set |
| `client_key_file` | `-client-key-file` | empty | path to a file holding this client's private key (`client_key` from `cmd/genkey`) — required if the server has auth enabled |
| `client_key` | — | empty | the same private key written directly into the config, instead of `client_key_file` |

`server-config.json`/`client-config.json`/`authorized_keys.json` are
gitignored — never commit the real files once they hold a live key;
only `*.example.json` (placeholder values) live in the repo. See
["Authentication"](#authentication) above for what
`insecure`/`pin_file`/`server_pin`/`authorized_keys_file` actually do.
