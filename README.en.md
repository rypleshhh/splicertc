RU [Русский](README.md) | EN **English**

# splicertc

A TCP/TLS tunnel for networks that block UDP and most ports but let TLS
through on mail ports (587, 993). The main `vpn` mode wraps all IPv4
traffic of a Windows machine in TLS to your own VPS. Game UDP goes over a
separate channel: every packet is sent as a copy over 2–3 parallel
connections and the server takes the first copy that arrives, so one TCP
loss doesn't hold game packets back.

## How it works

| Channel | Default port | Carries |
|---|---|---|
| vpn | `:8447` (`:587` in the example) | whole IPv4 packets; TUN + NAT on the server |
| glue | `:8446` | game UDP, multipath with deduplication |
| reliable | `:8443` | TCP connections of a local SOCKS5 proxy (smux) |
| droppable | off | test frames for loss measurements, logged only |

Any channel is disabled with `"off"`. Every connection is TLS 1.3; the
client checks the server by its certificate fingerprint (pin), the server
checks the client by an Ed25519 key. Inside the tunnel there is an
FQ-CoDel queue: small packets (game, DNS, ACKs) go before downloads.

Components: `cmd/server` (VPS, Docker), `cmd/client` (Windows),
`cmd/tray` (GUI for `vpn`), `cmd/genkey`, `cmd/gencert`, `cmd/portprobe`
(which ports the network lets through), `cmd/tunprobe` (what the TUN sees).

## Setup

### 1. Key

The client generates its own key, the private part never leaves the
machine. In the tray, "Новый ключ" (new key) puts the key into the field
and copies the line for the server to the clipboard. Without the tray:

```
go run ./cmd/genkey -name "me"
```

Send the `public_key` line to the server admin and keep `client_key`.
The public line for an existing `client_key`:
`go run ./cmd/genkey -name me -pub <client_key>`.

### 2. Server

Linux with Docker. Once on the host:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-dormtun.conf
sudo modprobe tcp_bbr
```

In the project folder:

```bash
cp server-config.example.json server-config.json
cp authorized_keys.example.json authorized_keys.json   # add the clients' public_key
go run ./cmd/gencert                                    # once; without Go: docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine go run ./cmd/gencert
docker compose up --build -d
docker compose logs -f
```

The certificate is not baked into the image. It lives in `devcerts/`, is
mounted into the container and survives rebuilds, so client pins keep
working. `gencert` won't overwrite an existing certificate without
`-force`; `-host vpn.example.com` makes one for your own name.
`server-config.json`, `authorized_keys.json` and `devcerts/` must exist
before the first start, otherwise Docker creates empty folders in their
place. On a fresh clone, save these three first.

The log should show `client authentication enabled`, the `... channel
listening on ...` lines and `cert fingerprint ...` (the fingerprint for
`server_pin`). Open the ports in the VPS firewall (`ufw allow 587/tcp`).
Without `authorized_keys_file` the server refuses to start, it would be an
open proxy.

### 3. Client (Windows)

```powershell
go build -o client.exe .\cmd\client
go build -ldflags "-H=windowsgui" -o tray.exe .\cmd\tray
```

Put `tray.exe`, `client.exe` and `wintun.dll` into a folder inside
Program Files. The tray runs as administrator and starts `client.exe` and
`wintun.dll` from its own folder; if a normal user can write there, any
program can swap these files and get admin rights. Outside Program Files
the tray warns once.

`wintun.dll` in the repository: version 0.14.1 from
https://www.wintun.net/, signed by WireGuard LLC, SHA-256
`E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`.

In the tray: name, server address (`IP:587`), key, games (optional),
"Подключиться" (connect). On the first connect the client remembers the
server certificate in `known_server.pin` and checks it from then on. Keys
in `connections.json` are encrypted with DPAPI for the current user;
`client-config.json` gets no key: the tray passes it to `client.exe` in
the `SPLICERTC_CLIENT_KEY` environment variable.

Without the tray: copy `client-config.example.json` to
`client-config.json`, set `vpn_addr` and `client_key`, run `.\run-vpn.ps1`
from an Administrator shell. If the tray already wrote that config, it
has no key: set `SPLICERTC_CLIENT_KEY` or keep a separate config for the
console (`.\run-vpn.ps1 -Config other.json`). The script takes the
lowest-metric default route outside the TUN as the real gateway, so
another active VPN can take its place.

## Game traffic

```json
"glue_addr": "<SERVER_IP>:993",
"game_processes": ["deadlock.exe"],
"game_paths": 3
```

The client asks Windows (`GetExtendedUdpTable`) which process owns a UDP
port and sends UDP of these processes over glue. The game's TCP and all
other traffic use `vpn`. The name must be exact, with `.exe`: Task
Manager, "Details" tab, or `Get-Process -Name "*deadlock*" | Select Path`.

The "glue or vpn" decision is made once per flow and never changes:
moving between channels changes the outside address and the game server
sees a new client. While the port owner is unknown, packets of that flow
are dropped; if no owner shows up within a second, the flow goes over vpn.
On the server the first game packet logs `glue: new flow ...`.

Whether multipath helps on a given network is a matter of measuring:
`tun` mode with `tun_measure: true` prints RTT, jitter and loss every 5
seconds. Compare `tun_paths: 1` and `3` at peak hours. All paths share
one dorm link, so their losses can be correlated.

## Latency under load and disconnects

To keep downloads from inflating ping:

- FQ-CoDel inside the tunnel on both sides;
- `TCP_NOTSENT_LOWAT` 16 KB and BBR on the server sockets (log `transport:
  tunnel sockets use BBR`; without BBR run `sudo modprobe tcp_bbr`);
- batched writes: several frames go out as one TLS record.

If ping still grows during downloads, the queue builds up in the
network's router. Set `vpn_down_mbps` (server) and `vpn_up_mbps` (client)
to 85–90% of the real link speed.

The client survives disconnects by itself. The vpn channel sends a
keepalive every 2 s and reconnects after 7 s of silence with a 0.5→5 s
backoff; the TUN and routes stay. Every glue path is pinged every 200 ms;
a path without an answer for 1 s is redialed, the others keep working. A
rejected key or a changed certificate stops the client right away:
retrying won't help, and with a wrong key it only leads to a ban. The
tray tells these apart and offers to reset the pin if the certificate was
regenerated on the server.

## Security

**The server is checked by pin.** `pin_file` remembers the fingerprint on
the first connect (like `known_hosts`); `server_pin` takes the
fingerprint from the server log by hand. With a CA certificate (Let's
Encrypt) no pin is needed, `server_name` is enough. `insecure: true`
without a pin checks nothing, tests only; the client logs a warning.

**The client is checked by key.** The signature is bound to the TLS
session (exporter), so it can't be replayed or relayed through an
interceptor. The server answers with an "accepted" byte, so a client
with a wrong key knows at once. Three wrong keys in a row from one IP
mean a 10 minute ban; IPv6 is banned per /64; an IP with a successful
login within the last 24 hours (the shared dorm NAT) is not banned.

**Where the server connects for a client** (`internal/egress` and the vpn
channel's iptables):

- not to loopback, link-local (cloud metadata) or multicast;
- not to the server's own addresses, including its public IP. In clouds
  with 1:1 NAT (AWS, GCP, Yandex Cloud) the public IP isn't on an
  interface, put it into `public_ips`;
- not to private networks `10/8`, `172.16/12`, `192.168/16`, `100.64/10`
  (unless `allow_private_destinations` is on), and not to TCP port 25;
- glue doesn't send UDP to amplifier ports (DNS, NTP, SSDP, memcached…);
- into the vpn channel only packets with the client's source address,
  towards the client only replies to its connections (conntrack);
- the iptables rules are mandatory: if one fails, the vpn channel doesn't
  start. The backend (legacy or nft) is picked from the host's rules.

**Resources.** The handshake is limited to 15 s. Limits: 512 UDP flows per
session, 4 sessions per client, 4096 flows per server, 256 smux streams
per connection. Docker logs: 3 files of 10 MB. Websites and game server
addresses are not logged.

**IPv6 and DNS.** The tunnel is IPv4 only. While connected, a firewall
rule blocks global IPv6 and apps fall back to IPv4. The TUN gets
interface metric 1, so DNS queries go to 1.1.1.1 through the tunnel
first. Windows doesn't allow ruling out queries to the dorm DNS
completely.

## Limitations

- One vpn client per server: the TUN has one client address. A reconnect
  with the same key replaces the old connection, another key is refused,
  so every device needs its own key.
- Normal traffic in vpn is TCP over TCP, with the usual trouble under
  loss. Games are protected from it by glue.
- The tunnel is visible to DPI: Go's standard TLS fingerprint, a
  self-signed certificate, TLS right away on port 587 without an SMTP
  banner.

## Other client modes

- **`socks5`**: local SOCKS5 on `127.0.0.1:1080` over the reliable channel.
  TCP CONNECT only, no admin rights, reconnects by itself.
- **`tun`**: all UDP from a TUN over glue, with `tun_paths` paths and
  `tun_measure` measurements. Route a game server by hand (`route add
  <GAME_IP> mask 255.255.255.255 <tun ip>`); never route the tunnel
  server itself through the TUN, it loops.
- **`droptest`**: synthetic frames to the droppable channel. Enable
  `drop_addr` on the server; add loss with `tc netem`.

## Diagnostics

`portprobe` finds the ports the network lets through. The server answers
with a token containing the port number, so a transparent proxy can't
pass for an open port.

```bash
./portprobe -mode server -tcp 1-999 -udp none                        # on the VPS, only while testing
.\portprobe.exe -mode client -host <SERVER_IP> -tcp 1-999 -udp none   # from the dorm network
```

`-sustain 5m` keeps the open ports under traffic, `-targets default`
checks public services without your own server. `tunprobe -name dormtun0`
prints the packets that reach the TUN.

## Config reference

### `server-config.json`

| Field | Default | What it does |
|---|---|---|
| `vpn_addr`, `glue_addr`, `addr`, `drop_addr` | `:8447`, `:8446`, `:8443`, `off` | addresses of the vpn, glue, reliable and droppable channels; `"off"` disables one. Without vpn no TUN, iptables or `NET_ADMIN` is needed |
| `authorized_keys_file` | — | the clients' keys, required |
| `cert`, `key` | `devcerts/dev.crt`, `devcerts/dev.key` | TLS certificate |
| `vpn_subnet` | `10.66.0.0/24` | vpn subnet: server `.1`, client `.2` |
| `vpn_tun_name`, `vpn_tun_mtu` | `dormvpn0`, `1400` | server TUN |
| `egress_iface` | auto | interface for MASQUERADE |
| `public_ips` | — | public IPs of the server that aren't on an interface (1:1 NAT) |
| `allow_private_destinations` | `false` | let clients into private networks behind the VPS |
| `vpn_down_mbps` | `0` | server→client rate cap, Mbit/s |

The `-allow-unauthenticated` flag (command line only) starts the server
without keys for a local test.

### `client-config.json`

| Field | Default | What it does |
|---|---|---|
| `mode` | `socks5` | `vpn`, `tun`, `socks5`, `droptest` |
| `vpn_addr`, `glue_addr`, `server`, `drop_addr` | localhost | channel addresses. A host name is resolved once, all channels use the same IP |
| `client_key`, `client_key_file` | — | client key, required. The `SPLICERTC_CLIENT_KEY` variable wins over both |
| `pin_file`, `server_pin` | — | server pin: TOFU file or a fingerprint by hand |
| `server_name` | host of the address | SNI and the name a CA certificate is checked against |
| `insecure` | `false` | without a pin don't check the certificate, tests only |
| `vpn_tun_name`, `vpn_tun_mtu` | `dormvpn0`, `1400` | client TUN |
| `vpn_subnet` | `10.66.0.0/24` | must match the server |
| `game_processes`, `game_paths` | —, `3` | game exes for glue and the number of paths |
| `vpn_up_mbps` | `0` | client→server rate cap, Mbit/s |
| `listen` | `127.0.0.1:1080` | SOCKS5 port (`socks5`) |
| `tun_name`, `tun_mtu`, `tun_paths`, `tun_measure`, `tun_measure_interval` | `dormtun0`, `1420`, `1`, `false`, `33ms` | `tun` mode |
| `drop_count`, `drop_interval`, `drop_paths` | `0`, `33ms`, `1` | `droptest` mode |

An unknown field in either config is an error at startup: a typo must
not silently leave the default. Command line flags with the same names
override config fields. Real configs and keys are in `.gitignore`; the
repository has only `*.example.json`.

## Development

```
go vet ./...
go test -race ./...
GOOS=linux go build ./cmd/server
```

CI (`.github/workflows/ci.yml`) runs gofmt, staticcheck, race tests on
Linux and Windows, govulncheck and a Docker image build on every push.
