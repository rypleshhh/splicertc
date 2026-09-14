# HANDOFF — tcp-dormtun

Read this first, then `README.md` (authoritative for exact commands —
if anything here disagrees with it, trust README.md). This document is
for picking the project back up in a new session; it captures context
that lives in conversation history, not in code comments.

## Goal

Personal Go project: a custom TCP/TLS tunnel to get better gaming
performance (lower loss/jitter) through a university dormitory network,
specifically *better than* the user's existing production VPN
(Xray VLESS+Reality + Hysteria2 + AmneziaWG, managed via an OpenWrt
router doing selective routing at home). Getting through the network at
all is not the hard part — the user already does that with Xray. The
point of this project is the droppable-channel + multipath-duplication
design, which the existing Xray setup doesn't have, to see if it
actually beats Xray on real gaming traffic.

## Physical topology

- **Client**: user's Windows desktop, inside the dorm network.
- **Production server**: VPS at `82.23.163.204` (Hostkey, Amsterdam),
  already running Xray on port 443 (systemd-managed, not 3x-ui anymore).
  This is the user's daily-driver tunnel — don't disrupt it carelessly.
- **Planned**: a separate, disposable rented VPS for testing this
  project in isolation, so experiments don't risk the production setup.

## Critical discovery: what the dorm network actually blocks

The original brief assumed "dorm blocks UDP by DPI signature, so we
need TCP." Live testing (see conversation, not reproduced in code)
found something more specific and more limiting:

**The dorm's outbound filter allows essentially only port 443 (and a
few other standard ports); everything else — TCP or not, doesn't
matter — gets silently dropped at the dorm's edge, before it ever
reaches the internet.**

Evidence: this project's own TLS tunnel on ports 8443/8444/8446/2053/
42083 all failed from the dorm Wi-Fi, but:
- The *same* ports succeeded immediately when the client was on mobile
  data instead of dorm Wi-Fi (different `SourceAddress` confirmed the
  network actually changed).
- An external public port-scanner (`ifconfig.co/port/<n>`) run from the
  VPS confirmed the ports were genuinely reachable from the wider
  internet — so it's not the VPS's firewall or the server code.
- Port 443 (occupied by the existing Xray) passed fine from the dorm
  the whole time.

**Implication: this tunnel is currently unusable from the dorm at all**,
regardless of how good the droppable/multipath logic is, until it also
runs on port 443. Since 443 on the main VPS is taken by Xray, the next
real step is **SNI-based TLS demultiplexing** — a thin front (sing-box,
sslh, or nginx `stream` module) inspecting the ClientHello SNI and
routing to either Xray or this tunnel's listener, both sharing the one
port. No code for this exists yet; it's infrastructure/config work, not
Go.

## Architecture (current state, matches the repo layout)

```
/cmd
  /client    — see modes below
  /server    — three independent TLS listeners
  /gencert   — throwaway self-signed dev cert generator
  /tunprobe  — standalone TUN packet-classification diagnostic (no tunnel)
/internal
  /transport — TLS dial/listen (plain crypto/tls, TLS1.3; NO utls/Reality
               fingerprint masking yet — brief step 4, not started)
  /frame     — droppable-channel wire format (seq + timestampMS + payload)
               + Receiver with TTL-based and supersession-based dropping.
               Tested.
  /proto     — length-prefixed target-address framing for the plain
               SOCKS5-over-tunnel (reliable channel) path
  /socks5    — minimal SOCKS5 server-side parsing (handshake + CONNECT
               only, no SOCKS5 auth negotiation — that's a different
               layer from this project's own PSK auth)
  /pktfilter — parses raw IPv4/IPv6 off a TUN device; classifies real
               traffic vs. local-discovery noise (mDNS/SSDP/NetBIOS/
               LLMNR/broadcast/multicast) via a NEGATIVE list (games use
               dynamic ports, so no positive allowlist is possible);
               also builds outgoing IPv4+UDP reply packets with a
               correct IP header checksum (UDP checksum left at 0, which
               is RFC-legal for IPv4). Tested.
  /glue      — envelope riding inside frame.Payload for REAL captured
               UDP: msgOutbound (client→server: dst ip:port + payload),
               msgInbound (server→client: reply payload), msgPing
               (RTT measurement nonce). DestinationAllowed() blocks
               loopback/link-local/multicast destinations and classic
               amplification-vector ports (DNS/NTP/memcached/SSDP/etc)
               — defense in depth regardless of auth. Tested.
  /measure   — RTT (min/mean/p95/max) + RFC3550-style smoothed jitter +
               loss, driven by glue's ping mechanism. Tested.
  /auth      — challenge-response PSK auth (HMAC-SHA256 over a
               server-issued random challenge), run immediately after
               the TLS handshake on ALL THREE server listeners, before
               any protocol logic. LoadKey() SHA-256-derives a fixed key
               from a passphrase file (never pass secrets as a bare CLI
               flag — visible via /proc/<pid>/cmdline to any local user).
               Tested.
  /mux, /config, /crypto — empty placeholders from the original brief's
               planned layout; smux (github.com/xtaci/smux) covers the
               reliable channel's multiplexing instead of custom code
               here; config/crypto never ended up needing their own code.
```

### Why three separate physical TLS connections, not one muxed connection

Deliberate, and based on a real lesson from the user's *existing* VPN
infra: mixing TCP web traffic and UDP game traffic over one muxed VLESS
connection there caused cross-contamination head-of-line blocking (a
stalled web request could stall game packets sharing the same physical
stream). Same principle applied here: reliable (SOCKS5/smux), droppable
(TTL-framed demo/test traffic), and glue (real captured UDP) are three
independent listeners/connections on the server, never sharing one pipe.

### Server (`cmd/server`) flags

`-addr` (reliable, default `:8443`), `-drop-addr` (`:8444`), `-glue-addr`
(`:8446`), `-cert`/`-key` (TLS), `-psk-file` (empty = auth disabled,
logs a loud warning at startup).

- **Reliable channel**: smux session per TLS conn; one smux stream per
  SOCKS5 app-connection; server does a plain `net.Dial` per stream.
- **Droppable channel**: sessions keyed by an 8-byte client-chosen
  session ID sent right after auth. N parallel connections sharing one
  ID dedupe against one shared `frame.Receiver` — this is what makes
  `-drop-paths N` multipath work. Tracks accepted / TTL-dropped /
  duplicate-suppressed counts *separately* — an early real bug conflated
  per-copy duplicate-suppression with genuine TTL loss, producing a
  wildly misleading "loss %" under multipath; fixed by counting distinct
  sequence numbers ever seen vs. ever delivered, not raw event counts.
- **Glue channel**: same session-ID grouping, generalized into
  `glueSession` — shared dedup receiver, shared map of live UDP flows
  (keyed by the captured packet's original source port as a "flow ID"),
  and a `paths` set of currently-connected conns that replies get
  broadcast across (dead paths silently pruned on write failure). Each
  flow gets one real `net.DialUDP` (after `checkAuth` +
  `DestinationAllowed` both pass), with one reader goroutine relaying
  whatever comes back.

### Client (`cmd/client`) modes

`-mode` = `socks5` (default) | `droptest` | `tun`. Common flags:
`-server`/`-drop-addr`/`-glue-addr`, `-insecure` (skip TLS cert
verification — currently the only cert option; no Reality-style pinning
yet), `-psk-file`.

- **socks5**: local SOCKS5 listener, forwards over smux. First MVP
  milestone, fully working.
- **droptest**: synthetic test harness for the droppable channel. Fixed-
  delay demo by default; `-drop-count`+`-drop-interval` for a real
  stress test (paired with external `tc netem` for genuine loss — no
  artificial sleep); `-drop-paths` for the multipath variant. This is
  what produced the loss numbers below.
- **tun**: the real integration. Creates a TUN interface via
  `github.com/tailscale/wireguard-go/tun` — the SAME Go code runs on
  Linux (`/dev/net/tun`) and Windows (`wintun.dll`); only the driver
  underneath differs. Reads raw packets, classifies via `pktfilter`, and
  for real (non-noise, IPv4, UDP) traffic: remembers the flow's original
  4-tuple, wraps the payload in `glue.EncodeOutbound`, wraps that in a
  `frame.Frame`, writes it to every open path (`-tun-paths N`, default
  1). A reader goroutine per path dedupes replies and reinjects them as
  a freshly built IPv4+UDP packet (`pktfilter.BuildIPv4UDP`) using the
  remembered flow info. `-tun-measure` (+`-tun-measure-interval`) sends
  `glue.EncodePing` frames on a timer and prints a summary every 5s —
  measuring ONLY the client↔server leg (not client↔server↔game-server),
  specifically so `-tun-paths 1` vs `-tun-paths 3` on the same real
  network is a clean, isolated comparison. **This is the intended
  methodology for finally getting real numbers on whether this beats
  Xray — not yet executed against real dorm conditions.**

## Real numbers already obtained (synthetic frames + real tc netem, on the VPS's own loopback)

TCP head-of-line blocking amplifies loss non-linearly for game-tick-rate
(33ms interval) traffic, because one lost segment stalls the whole
connection for a full RTO (Linux min RTO ≈200ms ≈ 6+ frames at that
rate), and this compounds as loss rate rises:

| netem loss | single-path "real loss" | 3-path multipath "real loss" |
|---|---|---|
| 3% | 5.3% | not run |
| 5% | 10.0% | not run |
| 20% | 87.3% | ~21–37% (two runs, noisy at n=300) |

Multipath duplication consistently cut loss by >2x at 20% netem loss.
This is the core evidence the project's premise (multipath beats plain
TCP tunneling) has legs — but only tested synthetically, never yet on
real dorm-network conditions or real game traffic.

## What's verified end-to-end, and how

- Bare TLS+smux+SOCKS5: real `curl` traffic through it. ✅
- Droppable TTL-drop: unit tests + live TLS test with artificial delays. ✅
- Netem loss numbers above: run directly on the VPS (loopback + `tc
  netem` on `lo`). ✅
- TUN capture + noise classification: live on Linux (dev sandbox) AND
  the user's real Windows machine (real `wintun.dll`) — real UDP test
  packets parsed correctly, real Windows background noise (mDNS/SSDP/
  NetBIOS/LLMNR) correctly suppressed into periodic summaries. ✅
- Full TUN → glue envelope → TLS tunnel → real UDP relay → real reply →
  reinjected into TUN → original test socket receives it: verified
  end-to-end in the Linux dev sandbox (loopback-alias trick standing in
  for "a real game server"), both single-path and 3-path multipath
  (10/10 packets round-tripped through 3 duplicated paths). **NOT yet
  run with the client on the real Windows machine against the real VPS
  over the actual dorm network** — this was next when the port-filtering
  discovery above derailed testing into a debugging detour. The
  mechanism is proven; it just hasn't been exercised over that exact
  real path yet.
- PSK auth + glue destination policy: unit tests + a live 3-scenario
  check (correct key passes, wrong key rejected, no key rejected) on
  loopback. Not adversarially tested beyond that.

## Not done yet

1. **utls/Reality-style TLS fingerprint masking** (original brief step
   4). Plain `crypto/tls` + self-signed dev cert + client `-insecure`
   right now. Possibly lower priority than #2 below — TBD with the user.
2. **Sharing port 443 with the production Xray via SNI demux** — now
   understood to be the actual blocker for using this tunnel from the
   dorm AT ALL (see the port-filtering discovery). No code written.
   Systems/config work (sing-box or sslh or nginx `stream`), not Go.
3. **Real-game / real-network validation with `-tun-measure`** — the
   whole point of the `measure` package. Plan was: rent a disposable
   box, run the server there via Docker (auth enabled), run
   `-tun-measure` from the dorm at `-tun-paths 1` then `-tun-paths 3`,
   compare. Not yet executed.
4. **Fallback server list + health-check + auto-switch** (brief step 5).
   Not started.
5. **Automated loss-simulation test suite** (brief step 6: `tc netem` /
   `go test`-driven). Done manually and informally, not as a repeatable
   test in the repo.
6. **Docker packaging** exists for the server only (`Dockerfile`,
   `docker-compose.yml`, `.dockerignore`) — deliberately not attempted
   for the client's `tun` mode (Docker Desktop's Linux VM on Windows has
   no path to a host Wintun adapter). The Dockerfile itself has NOT
   been build-tested (no Docker in the dev sandbox) — only the static
   Linux binary it packages was cross-compiled and confirmed clean.

## Open questions to resume with the user

- SNI-sharing 443 with the existing systemd-managed Xray: does a
  sing-box/sslh front fit cleanly, or would a second VPS IP from
  Hostkey be simpler if available?
- Priority: real-game measurement on a rented box first (validate the
  core premise) vs. finishing the 443-sharing work first (needed for
  ANY use of this tunnel from the dorm, including the already-working
  plain SOCKS5 mode, which hasn't even been load-tested against Xray
  head-to-head yet).
- `-tun-paths N` multiplies bandwidth N×. Hasn't been discussed against
  the user's actual dorm data constraints, if any exist.

## Working notes for whoever continues this

- User prefers dense, direct, technical answers — no hand-holding once
  they're past learning a new concept.
- Early in the project they deliberately did a "teach me Go" phase
  (typing code themselves, line-by-line explanations); switched to
  "just build and test it, I'll run and ask" once past the SOCKS5 MVP,
  and that's the current mode.
- Strong existing networking/VPN background (runs their own Xray+Reality
  +Hysteria2+OpenWrt selective-routing setup) — explain Go-specific
  things, not networking fundamentals.
- Every deliverable so far was actually built and tested (unit tests
  where feasible, live loopback/sandbox/real-machine runs otherwise)
  before being handed off — keep that bar.
