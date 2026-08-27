# topology

Scan the local network and render it as an interactive topology tree in the browser.

![tree](docs/screenshot.png)

- **Discovery** via `nmap` when it is installed, with a pure-Node ICMP + TCP + ARP sweep as a fallback.
- **Names** for devices a router does not publish DNS for, using unicast mDNS (5353) and NetBIOS (137) queries.
- **Identification** of what each device probably *is* — router, printer, camera, NAS, phone, IoT — from MAC vendor, hostname, open ports and OS fingerprint, with the reasoning shown in the UI.
- **Uplink** path above the gateway from `traceroute`, so the map shows where your LAN ends.
- **Traffic**, on a second tab: who is actually talking to whom, how much, and
  about what — from a live `tcpdump` capture, or from this machine's open
  sockets when there is no root.
- **Zero runtime dependencies.** Node 18+ and nothing from npm.

## Quick start

```bash
node src/cli.js            # scan, then serve the map on http://127.0.0.1:4173
```

Or as two steps:

```bash
node src/cli.js scan       # print the tree, write data/latest.json
node src/cli.js serve      # explore the saved scan in the browser
```

`npm start`, `npm run scan`, `npm run serve` and `npm run traffic` are the
same commands.

The map has two tabs: **Topology**, the tree of what is on the network, and
**Traffic**, a live graph of what is moving across it. `t` switches between them.

```bash
node src/cli.js traffic --seconds 30 --sudo    # same data, in the terminal
```

## Why `sudo` matters

Unprivileged `nmap` can only find hosts that answer a TCP connect on a common
port. With root it uses **ARP** on the local segment, which finds essentially
every powered-on device, plus SYN scanning and OS fingerprinting:

```bash
sudo -v                              # prime the sudo timestamp once
node src/cli.js scan --sudo --profile deep
```

The scanner never prompts for a password — it uses `sudo -n` and falls back to
unprivileged mode if that fails, noting it in the warnings. The web UI has a
matching **Use `sudo -n`** checkbox.

The traffic view needs root for a different reason: opening a capture device.
Without it there are no packets and no byte counts, only a list of the sockets
this machine has open. Both degrade the same way — automatically, and with the
downgrade stated on screen rather than hidden.

## CLI

```
topology scan    [options]   Run a scan, print the tree, save JSON
topology traffic [options]   Watch live traffic, print the busiest flows
topology serve   [options]   Serve the interactive web map
topology                     Same as: topology serve --scan
```

| Option | Meaning |
| --- | --- |
| `--target <cidr>` | Subnet or host to scan, repeatable. Default: every local IPv4 subnet that is not a tunnel. |
| `--profile quick` | Host discovery only. Seconds. |
| `--profile normal` | Discovery + top 100 ports. *(default)* |
| `--profile deep` | Discovery + top 500 ports + `-sV` service versions + OS detection. |
| `--sudo` | Run nmap through `sudo -n`. |
| `--no-traceroute` | Skip the uplink trace. |
| `--trace-target <ip>` | Traceroute destination (default `1.1.1.1`). |
| `--max-hosts <n>` | Refuse to auto-scan subnets larger than this (default 4096). |
| `--group category\|vendor\|none` | Grouping for the printed tree. |
| `--out <file>` | JSON destination (default `data/latest.json`). |
| `--json` | Print the model instead of the tree. |
| `--port` / `--host` | Server bind address (default `127.0.0.1:4173`). |
| `--scan` / `--open` | Scan on startup / open a browser. |

`topology traffic` takes its own set:

| Option | Meaning |
| --- | --- |
| `--seconds <n>` | How long to capture. Default 20. |
| `--iface <name>` | Interface to capture on, repeatable. Default: every local non-tunnel interface. |
| `--filter <bpf>` | Extra BPF expression, e.g. `'not port 22'`. |
| `--sudo` | Run `tcpdump` through `sudo -n`. Without it there is no capture. |
| `--limit <n>` | Rows of flow table to print (default 25). |
| `--json` | Print the flow snapshot instead of the table. |

The table names devices from the last saved scan, so run `topology scan` first
if you would rather read hostnames than addresses.

## The web map

```
┌───────────────┬──────────────────────────────────────────────────┐
│               │  Topology  │  Traffic                            │
│ scan controls ├──────────────────────────────────────────────────┤
│ summary       │ search · group · expand/collapse · zoom · export │
│ type legend   ├──────────────────────────────────────────────────┤
│ warnings      │   this machine → gateway → device groups         │
│               │                 └ uplink → hop → Internet        │
└───────────────┴──────────────────────────────────────────────────┘
```

The sidebar swaps with the tab: scan controls alongside the tree, capture
controls alongside the traffic graph.

- **Click** a node to open its details; a node with children also expands/collapses.
- **Search** matches hostname, IP, MAC, vendor, OS, port number and service name, and prunes the tree to matching branches.
- **Group** by device type, by vendor, or flat.
- **Legend** entries filter the map by device type.
- **Export** the current map as a standalone SVG, or the scan as JSON.
- Keys: `/` search, `f` fit, `e` expand all, `c` collapse all, `t` switch tab,
  `Esc` close.

Live scan progress streams to the page over SSE, so you can watch nmap's own
percentage while it works.

### HTTP API

| Route | Purpose |
| --- | --- |
| `GET /api/topology` | The latest scan model (falls back to `data/latest.json`). |
| `POST /api/scan` | Start a scan. Body: `{profile, sudo, targets[]}`. `409` if one is running. |
| `GET /api/events` | SSE stream of `phase` / `progress` / `model` / `error` / `idle` events. |
| `GET /api/health` | Liveness plus whether a scan is in flight. |
| `GET /api/traffic` | Latest flow snapshot, plus the vantage point it came from. |
| `POST /api/traffic/start` | Start a capture. Body: `{seconds, sudo, ifaces[], filter}`. `409` if one is running. |
| `POST /api/traffic/stop` | Stop the running capture and return the final snapshot. |
| `GET /api/traffic/events` | SSE stream of `traffic-started` / `traffic-phase` / `traffic-snapshot` / `traffic-warning` / `traffic-stopped` / `traffic-idle`. |

Traffic gets its own event stream because a snapshot arrives every second and is
large; mixing them into `/api/events` would push the scan events a late client
replays out of the buffer.

The server binds to loopback by default and serves only `web/` plus four
allow-listed modules from `src/lib/`. Interface names and BPF expressions from
the API are pattern-checked before they reach a command line.

## How the tree is built

The tree is what the scan can actually prove, from this machine's vantage point:

```
this machine
└── default gateway (the router that owns your subnet)
    ├── uplink → hop 2 → hop 3 → … → Internet      (from traceroute)
    └── device groups → devices                     (everything on the subnet)
```

Every additional interface with its own subnet — a second NIC, a VM bridge —
becomes another branch. Tunnel interfaces (`utun`, `wg`, `tun`, `ipsec`) are
skipped and reported in the warnings, since scanning through a VPN reaches
someone else's network.

Switch-level topology (which port a device is plugged into) is not discoverable
from a host without SNMP or LLDP access to the switches, so the map does not
invent it.

`src/lib/topology.js` builds the tree and is served to the browser as
`/shared/topology.js`, so the terminal output and the web map come from one
implementation.

## Device identification

Signals are weighted and combined; the winning category and the reasons that
picked it are both stored, and the drawer shows them under **Why this type**.

| Signal | Example |
| --- | --- |
| Default gateway | → Router, high confidence |
| MAC vendor | `Hikvision` → camera, `Espressif` → IoT, `Synology` → NAS |
| Hostname | `Tals-iPhone.local` → phone, `HP-LaserJet` → printer |
| Open ports | 631/9100 → printer, 554 → camera, 8009 → Chromecast, 1400 → Sonos |
| OS fingerprint | `Windows`, `embedded`, `Linux` |

MAC vendors come from nmap's `nmap-mac-prefixes` database (~52k prefixes) when
nmap is installed, otherwise from a small built-in table. Locally-administered
MACs are reported as *randomized* rather than guessed at — modern phones and
laptops rotate them per network.

Names are resolved from three sources, best first: mDNS, NetBIOS, reverse DNS.
The `Name via` field in the drawer says which one answered.

## The traffic map

The topology tree answers *what is on this network*. The traffic tab answers
*what is it doing* — a force-directed graph where each node is an endpoint and
each edge is a conversation.

- **Node size** is how much that endpoint moved; **edge width** is how much
  crossed that conversation; **edge colour** is what kind of traffic dominated
  it (web, DNS, discovery, file sharing, remote access, media, ICMP).
- **Node identity** comes from the last scan, matched on hardware address, IP or
  name, so a bare `192.168.1.241` shows up as `sonos-living` with the right icon.
  See [Matching traffic to devices](#matching-traffic-to-devices).
- **Click** a node or an edge for the breakdown: direction split, packets, top
  ports, per-type volume, a per-second sparkline, and — for anything this
  machine is an end of — the processes responsible.
- **Drag** a node to pin it, double-click to release. **Pause** freezes the map
  without stopping the capture.
- While a capture runs the panel shows its progress — a bar counting towards the
  end of a fixed window, or a sweep for *until stopped* — with a running total of
  bytes, packets and conversations, so a quiet network still looks alive. The
  start button is disabled for the duration, since the popup and the sidebar
  share one control and a stray second click would otherwise stop the capture.
- The Internet side collapses into one node by default, since a browser session
  produces dozens of CDN endpoints that add hairball and no information. The
  toolbar switches to one node per endpoint.
- `Show in topology →` in an endpoint's drawer jumps to that device in the tree.

### What a capture can and cannot see

This is the part of the app most able to mislead, so the vantage point is stated
in the sidebar rather than left implied:

| Method | Needs | Sees | Measures |
| --- | --- | --- | --- |
| `tcpdump` | root | this machine's traffic, plus every broadcast and multicast frame on the segment | bytes and packets |
| open sockets | nothing | conversations this machine is one end of | connection counts, no bytes |

The limit worth internalising: **on a switched network, two other devices
talking to each other are invisible from here.** A switch does not forward their
unicast frames to this port. What you do see of other devices is their broadcast
and multicast chatter — ARP, mDNS, SSDP, DHCP — which is enough to place them on
the map and say what they are looking for, but not to measure what they transfer.
Getting the full picture needs a mirror port or SNMP on the switch, which this
tool does not attempt, exactly as it does not invent switch-level topology.

When there is no capture, every number in the view is a count of connections
rather than bytes, and the UI relabels itself accordingly — `conns` instead of
`bytes`, no rate column — so the two can never be mistaken for each other.

Tunnel interfaces are skipped, as they are for scanning: capturing on a VPN
records someone else's network.

### Matching traffic to devices

A capture and a scan do not see a device the same way. The scan knows it by the
address it answered on; the wire shows a hardware address. Endpoints are matched
against the scan on three keys, in descending order of trust:

| Key | Why it ranks there |
| --- | --- |
| **MAC** | Observed *now*, carrying the actual traffic. Survives a DHCP lease change, and is shared by a device's IPv4, IPv6 and link-local addresses. |
| **IP** | Only says where the device was when the scan ran. |
| **Name** | Compared case-insensitively and without the `.local` suffix, against every alias the scan collected. |

Two consequences worth knowing about:

**Addresses collapse.** A device usually appears on the wire under several
addresses — IPv4, an IPv6 link-local, sometimes a fresh DHCP lease. Matching on
MAC is what lets those become the one device they actually are instead of three
strangers on the map. The drawer lists which addresses were folded together. The
same applies to well-known multicast groups, where `224.0.0.251` and `ff02::fb`
are one mDNS group under two addresses.

**A stale match is refused rather than guessed.** If an address matches a scanned
device but the hardware address on the wire is a *different* one, the lease has
moved or the scan is out of date. Naming that endpoint after the scan's device
would be a confident lie, so it is left unidentified and the drawer says why.

Where a MAC belongs to no scanned device, its OUI still names a maker, so an
unscanned board shows up as an *Espressif device* rather than a bare address.
The drawer's **How this was identified** section spells out which key matched and
what else was noticed, the same way the topology view explains **Why this type**.

One trap this deliberately avoids: a packet to or from the Internet carries the
*router's* MAC in its frame, not the remote host's. Hardware addresses are
therefore only ever recorded for addresses on the local segment — otherwise
every external host on the map would be confidently labelled as the gateway.
Group MACs (broadcast, `01:00:5e:…`, `33:33:…`) are excluded for the same reason:
they name a set, not a device.

The connection-sampling fallback sees no hardware addresses at all, so it matches
on IP alone. Search matches all of it — name, IP, MAC, vendor, port and process.

### Aggregation

Packets are folded into undirected flows keyed on the endpoint pair, each
carrying counters in both directions, a per-type and per-port breakdown, and a
90-second ring of per-second totals for the sparklines. The table is capped and
evicts the least-recently-seen flows under pressure; anything dropped is
reported in the notes rather than silently lost.

`src/lib/flows.js` does all of this and, like `topology.js`, is served to the
browser as `/shared/flows.js`, so the terminal table and the web graph are built
from one implementation.

## Project layout

```
src/cli.js               argument parsing, terminal output, entry point
src/server.js            static server + JSON API + SSE streams
src/scan/index.js        scan pipeline: survey → discover → probe → enrich → tree
src/scan/nmap.js         nmap driver and XML result parsing
src/scan/pingsweep.js    dependency-free fallback scanner
src/traffic/index.js     traffic monitor: picks a method, aggregates, snapshots
src/traffic/tcpdump.js   capture driver and packet-line parsing (3 tiers)
src/traffic/connections.js  open-socket sampling and process attribution
src/lib/topology.js      flat model → tree (shared with the browser)
src/lib/flows.js         packets → flows → graph, endpoint identity (shared)
src/lib/mac.js           MAC formatting and address-type tests (shared)
src/lib/classify.js      device-type inference (shared with the browser)
src/lib/names.js         mDNS / NetBIOS / reverse-DNS name resolution
src/lib/oui.js           MAC → vendor
src/lib/net.js           interfaces, routes, CIDR math
src/lib/xml.js           minimal XML parser for nmap output
web/app.js               topology tree view + tab shell
web/traffic.js           traffic graph view
web/canvas.js            pan/zoom/fit and SVG export, shared by both views
data/latest.json         most recent scan
```

## Troubleshooting

**Few devices found.** Run with `--sudo` — unprivileged discovery misses
anything that ignores TCP connects. Wireless clients that are asleep also stay
invisible until they talk again; the ARP cache picks them up on the next scan.

**No hostnames.** Most consumer routers publish no PTR records. mDNS and
NetBIOS fill the gap, but some devices answer neither. A device with no name is
still fully identified by MAC vendor and ports.

**Everything lands in "Unidentified".** That is the honest answer for a `quick`
scan, which never looks at ports. Use `normal` or `deep`.

**A scan seems stuck.** Progress is reported per phase in the sidebar and the
terminal. `nmap`'s own ETA is shown during discovery and probing; a `/24` at the
`deep` profile legitimately takes several minutes.

**The traffic map only shows this machine.** That is the unprivileged mode
working as designed. Prime `sudo -v` and tick **Use `sudo -n`**, and other
devices appear as soon as they broadcast.

**Traffic shows "conns" instead of bytes.** Same cause: no capture, so there are
no byte counts to show. The sidebar's vantage panel says which method is running.

**The traffic map says "Nothing matches".** A search or a traffic-type filter is
hiding everything the capture found. The card offers a button to clear both.
This is deliberately worded differently from an empty capture, because
conflating the two makes a working capture look dead.

**The traffic map is empty specifically when using sudo.** A capture is running
but its output is not being read. Since tcpdump's text format varies by build —
Apple's, for one, prints the interface and direction between the timestamp and
the link-layer header — the parser matches position-independently and reports a
format it cannot read as a warning in the sidebar, rather than leaving the map
looking merely quiet. If you see such a warning, the example line it quotes is
what the parser needs to handle.

**A traffic endpoint shows as an address instead of a device name.** Either the
scan never saw it — run `topology scan` — or its hardware address contradicts
what the scan recorded for that address, in which case the drawer says so and
leaves it unnamed on purpose. The connection-sampling fallback also has no MACs
to match on.

**A device is on the topology tree but not the traffic map.** It has not sent
anything the capture point can see during the window. Devices that only talk
unicast to each other, or that are simply idle, will not appear.

**Everything lands in "Discovery".** A quiet network is mostly mDNS, SSDP and
ARP chatter. That is a real answer rather than a failure — filter the legend to
see what else is moving.

## Scope and consent

Scan networks you own or are authorised to test. Discovery here is ordinary ARP,
ICMP and TCP traffic — nothing exotic — but it is still traffic on someone's
network, and a port scan is visible to any IDS worth its name. Tunnel interfaces
are skipped by default for exactly this reason.

Capturing goes further than scanning: a scan produces traffic of its own, while a
capture reads other people's as it passes, including packets not addressed to
this machine. The same rule applies, with less room for argument — capture on
networks you are responsible for. The capture is header-only (`-s 128`), so
payloads are never read, and nothing is written anywhere except the snapshot you
explicitly export. Tunnel interfaces are skipped here too.
