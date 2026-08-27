import { run, has } from '../lib/exec.js';

/**
 * tcpdump driver: spawns a line-buffered capture and turns each line into a
 * packet record for FlowTable.
 *
 * Parsing tcpdump's text output is less pleasant than reading pcap directly,
 * but pcap needs a native addon and this project has no dependencies. `-e` is
 * requested so every packet reports its frame length in the same place, and so
 * ARP frames can be attributed to a MAC.
 */

const ETHER_MAC = '[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}';

// A leading timestamp in any of the formats the -t flags produce. Only used to
// strip it: the arrival time is used for bucketing instead, so a build whose
// timestamp format we do not recognise still yields usable packets.
const LEAD_TIMESTAMP = /^(?:\d{4}-\d{2}-\d{2}\s+)?(\d+\.\d+|\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+/;

// aa:bb:.. > ff:ff:.., ethertype IPv4 (0x0800), length 74: <payload>
//
// Deliberately NOT anchored to the start of the line. Apple's tcpdump captures
// through PKTAP and prints the interface name and direction between the
// timestamp and the link-layer header; other builds add VLAN or tunnel
// decoration there. Anchoring this made every line on macOS fail to parse,
// which surfaced as a silently empty traffic map rather than an error.
const FRAME = new RegExp(
  `(${ETHER_MAC})\\s+>\\s+(${ETHER_MAC}),\\s+` +
  `(?:.*?ethertype\\s+(\\S+)\\s+\\(0x[0-9a-f]+\\),\\s+)?length\\s+(\\d+):\\s*(.*)$`,
  'i',
);

// Fallback for captures with no link-layer header (loopback, `-i any`):
// 1724750000.123456 IP 192.168.1.5.443 > 192.168.1.7.51000: tcp 0
const BARE = /\b(IP6?|ARP|RARP)\s+(.*)$/i;

// A VLAN- or MPLS-tagged frame nests a second `ethertype X (0x..), length N:`
// header inside the payload; without unwrapping it the inner header ends up
// parsed as part of the source address.
const NESTED_HEADER = /^(?:(?:vlan \d+|p \d+|mpls \(label \d+[^)]*\)|pppoes \d+),\s+)*ethertype\s+(\S+)\s+\(0x[0-9a-f]+\),\s+length\s+(\d+):\s*/i;

// With -q a bare TCP line reports its payload length as `tcp 517`, while UDP
// and the rest use a trailing `length N`.
const PAYLOAD_LENGTH = /(?:length (\d+)|\btcp (\d+))\s*$/;

// Last resort: any `A > B: description` pair, for a build that prints neither a
// link-layer header nor an `IP` keyword. Guarded by isAddressLike so a stray
// `MAC > MAC` line cannot be read as a conversation between two addresses.
const GENERIC = /(\S+)\s+>\s+([^\s:]+(?::[^\s:]+)*?):\s+(.*)$/;

const ARP_REQUEST = /^Request who-has (\S+) tell ([^,\s]+)/i;
const ARP_REPLY = new RegExp(`^Reply (\\S+) is-at (${ETHER_MAC})`, 'i');
const ARP_GRATUITOUS = /^Reply (\S+) is-at/i;

/** True if tcpdump is on PATH. */
export function tcpdumpAvailable() {
  return has('tcpdump');
}

export function isPrivileged() {
  return typeof process.getuid === 'function' ? process.getuid() === 0 : false;
}

/** `sudo -n true` succeeds only when a sudo timestamp is already cached. */
export async function sudoAvailable() {
  if (isPrivileged()) return true;
  const res = await run('sudo', ['-n', 'true'], { timeout: 5000 });
  return res.ok;
}

/**
 * Reasons a capture cannot start, phrased for a human rather than a log.
 * Returned rather than thrown: the monitor degrades to netstat instead.
 */
export function explainFailure(stderr) {
  const text = String(stderr || '');
  if (/a (?:terminal|password) is required|sudo: /i.test(text)) {
    return 'sudo -n has no cached credentials, so packet capture could not start. Run `sudo -v` in a terminal first.';
  }
  if (/permission denied|operation not permitted|bpf/i.test(text)) {
    return 'No permission to open the capture device. Packet capture needs root — use sudo.';
  }
  if (/no such device|siocgifflags|not found/i.test(text)) {
    return 'The capture interface does not exist or is down.';
  }
  const first = text.split('\n').map((l) => l.trim()).filter(Boolean)[0];
  return first ? `tcpdump: ${first}` : 'tcpdump exited without capturing anything.';
}

/**
 * Start a capture on one interface.
 *
 * @param {object} options
 * @param {string} options.iface       interface name, e.g. en0
 * @param {boolean} options.sudo       run through `sudo -n`
 * @param {string|null} options.filter BPF expression
 * @param {number} options.snaplen     bytes captured per packet; we only read headers
 * @param {(packet: object) => void} options.onPacket
 * @param {(message: string) => void} options.onError
 * @param {() => void} options.onReady  fired on the first parsed packet
 * @returns {{stop: () => void, iface: string, stats: object}}
 */
export function capture({
  iface,
  sudo = false,
  filter = null,
  snaplen = 128,
  maxPacketsPerSecond = 20000,
  onPacket = () => {},
  onError = () => {},
  onReady = () => {},
} = {}) {
  const args = ['-n', '-e', '-q', '-tt', '-l', '-s', String(snaplen), '-i', iface];
  if (filter) args.push(filter);

  const useSudo = sudo && !isPrivileged();
  const cmd = useSudo ? 'sudo' : 'tcpdump';
  const argv = useSudo ? ['-n', 'tcpdump', ...args] : args;

  const stats = {
    iface,
    lines: 0,
    parsed: 0,
    unparsed: 0,
    rateLimited: 0,
    noLinkLayer: 0,
    command: `${cmd} ${argv.join(' ')}`,
  };

  // MAC -> IP, learned as packets go by, so an ARP reply (which is unicast to a
  // MAC and names no destination IP) can still be attributed to a peer.
  const macToIp = new Map();

  let ready = false;
  let stderr = '';
  let buffer = '';
  let windowStart = 0;
  let windowCount = 0;
  let stopped = false;

  // Lines arriving but never parsing means the output format is not one this
  // parser knows. Left unreported it is indistinguishable from a quiet network,
  // which is exactly how an anchored regex once produced an empty map on macOS.
  const watchdog = setTimeout(() => {
    if (stopped || ready || stats.lines === 0) return;
    onError(
      `tcpdump on ${iface} produced ${stats.lines} lines that this parser could not read, `
      + 'so the output format is not one it recognises. Falling back to connection sampling.'
      + (stats.sample ? ` Example: ${stats.sample}` : ''),
    );
  }, 4000);

  const child = spawnCapture(cmd, argv, {
    onStdout: (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        stats.lines += 1;

        // A flood should cost us dropped samples, not the event loop.
        const second = Math.floor(Date.now() / 1000);
        if (second !== windowStart) {
          windowStart = second;
          windowCount = 0;
        }
        if (++windowCount > maxPacketsPerSecond) {
          stats.rateLimited += 1;
          continue;
        }

        const packet = parseLine(line, macToIp, stats, Date.now());
        if (!packet) {
          stats.unparsed += 1;
          continue;
        }
        stats.parsed += 1;
        if (!ready) {
          ready = true;
          clearTimeout(watchdog);
          onReady();
        }
        onPacket(packet);
      }
    },
    onStderr: (chunk) => {
      stderr += chunk;
      if (stderr.length > 8192) stderr = stderr.slice(-8192);
    },
    onExit: (code) => {
      if (stopped) return;
      if (!ready) onError(explainFailure(stderr || `exit code ${code}`));
      else if (code !== 0 && code !== null) onError(explainFailure(stderr));
    },
    onSpawnError: (err) => onError(`tcpdump could not start: ${err.message}`),
  });

  return {
    iface,
    stats,
    stop() {
      stopped = true;
      clearTimeout(watchdog);
      child.kill();
    },
  };
}

/** Thin spawn wrapper; exec.js buffers to completion, and a capture never ends. */
function spawnCapture(cmd, args, { onStdout, onStderr, onExit, onSpawnError }) {
  let child = null;
  import('node:child_process').then(({ spawn }) => {
    try {
      child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      onSpawnError(err);
      return;
    }
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', onStdout);
    child.stderr.on('data', onStderr);
    child.on('error', onSpawnError);
    child.on('close', onExit);
  });

  return {
    kill() {
      // `sudo tcpdump` runs tcpdump as a child of sudo; SIGTERM to sudo is
      // forwarded, but SIGKILL would orphan the capture, so never escalate.
      try {
        child?.kill('SIGTERM');
      } catch {
        /* already gone */
      }
    },
  };
}

/* ------------------------------------------------------------------- parsing */

/**
 * One tcpdump line -> a packet record, or null.
 *
 * @param {string} line
 * @param {Map} macToIp   learned MAC -> IP, for attributing ARP replies
 * @param {object} stats   mutated with counters and a sample of what failed
 * @param {number} at      arrival time; used rather than the printed timestamp
 */
export function parseLine(line, macToIp = new Map(), stats = {}, at = Date.now()) {
  // Strip the timestamp so it cannot be mistaken for part of an address, but
  // do not require one: `-t` suppresses it entirely.
  const body = line.replace(LEAD_TIMESTAMP, '');

  const frame = body.match(FRAME);
  if (frame) {
    const [, srcMac, dstMac, ethertype, length, payload] = frame;
    const inner = unwrapTags((ethertype || '').toLowerCase(), payload);
    return fromPayload({
      at,
      // The outer length is the number of bytes actually on the wire, tags
      // included, so it stays even when the inner header wins the ethertype.
      bytes: Number(length),
      srcMac: srcMac.toLowerCase(),
      dstMac: dstMac.toLowerCase(),
      ethertype: inner.ethertype,
      payload: inner.payload,
      macToIp,
    });
  }

  const bare = body.match(BARE);
  if (bare) {
    const [, kind, payload] = bare;
    const packet = fromPayload({
      at,
      bytes: 0,
      srcMac: null,
      dstMac: null,
      ethertype: kind.toLowerCase() === 'arp' ? 'arp' : 'ipv4',
      payload,
      macToIp,
    });
    if (packet) {
      stats.noLinkLayer = (stats.noLinkLayer || 0) + 1;
      // No frame header, so the only size on the line is the payload length.
      const tail = payload.match(PAYLOAD_LENGTH);
      packet.bytes = tail ? Number(tail[1] ?? tail[2]) : 0;
      packet.estimatedBytes = true;
      return packet;
    }
  }

  const generic = body.match(GENERIC);
  if (generic) {
    const packet = fromPayload({
      at,
      bytes: 0,
      srcMac: null,
      dstMac: null,
      ethertype: 'ipv4',
      payload: `${generic[1]} > ${generic[2]}: ${generic[3]}`,
      macToIp,
    });
    if (packet && isAddressLike(packet.src) && isAddressLike(packet.dst)) {
      stats.noLinkLayer = (stats.noLinkLayer || 0) + 1;
      const tail = body.match(PAYLOAD_LENGTH);
      packet.bytes = tail ? Number(tail[1] ?? tail[2]) : 0;
      packet.estimatedBytes = true;
      return packet;
    }
  }

  // Keep one example of what could not be read. Without it, an output format
  // this parser does not understand is indistinguishable from a silent network.
  if (!stats.sample && /\s>\s/.test(line)) stats.sample = line.slice(0, 200);
  return null;
}

/** An IPv4 or IPv6 address, and specifically not a MAC. */
export function isAddressLike(value) {
  const text = String(value || '');
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return true;
  if (!text.includes(':')) return false;
  // aa:bb:cc:dd:ee:ff is six single-colon hex groups; an IPv6 address is not.
  if (/^[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}$/i.test(text)) return false;
  return /^[0-9a-f:]+$/i.test(text) || text.includes('::');
}

/** Peel VLAN/MPLS shims so the innermost ethertype and payload are used. */
function unwrapTags(ethertype, payload) {
  let type = ethertype;
  let rest = payload;
  for (let depth = 0; depth < 4; depth++) {
    const match = rest.match(NESTED_HEADER);
    if (!match) break;
    type = match[1].toLowerCase();
    rest = rest.slice(match[0].length);
  }
  return { ethertype: type, payload: rest };
}

function fromPayload({ at, bytes, srcMac, dstMac, ethertype, payload, macToIp }) {
  if (!Number.isFinite(at) || at <= 0) return null;

  if (ethertype.startsWith('arp') || ethertype.startsWith('rarp')) {
    return parseArp({ at, bytes, srcMac, dstMac, payload, macToIp });
  }

  const arrow = payload.indexOf(' > ');
  if (arrow === -1) return null;
  const srcToken = payload.slice(0, arrow).trim();
  const rest = payload.slice(arrow + 3);

  // An IPv6 address contains ':' but never ': ', so the first colon-space is
  // reliably the end of the destination token.
  const split = rest.match(/^(.+?):\s(.*)$/) || rest.match(/^(.+?):$/);
  if (!split) return null;
  const dstToken = split[1].trim();
  const description = (split[2] || '').trim();

  const protocol = protocolOf(description, ethertype);
  const hasPorts = protocol === 'tcp' || protocol === 'udp';
  const src = splitAddress(srcToken, hasPorts);
  const dst = splitAddress(dstToken, hasPorts);
  if (!src.address || !dst.address) return null;

  if (srcMac) macToIp.set(srcMac, src.address);

  return {
    at,
    bytes,
    src: src.address,
    dst: dst.address,
    srcPort: src.port,
    dstPort: dst.port,
    protocol,
    srcMac,
    dstMac,
  };
}

function parseArp({ at, bytes, srcMac, dstMac, payload, macToIp }) {
  const request = payload.match(ARP_REQUEST);
  if (request) {
    const [, target, sender] = request;
    if (srcMac) macToIp.set(srcMac, sender);
    return { at, bytes, src: sender, dst: target, protocol: 'arp', srcMac, dstMac };
  }

  const reply = payload.match(ARP_REPLY) || payload.match(ARP_GRATUITOUS);
  if (reply) {
    const sender = reply[1];
    if (srcMac) macToIp.set(srcMac, sender);
    // The reply is unicast to a MAC; the peer IP is whatever we have learned
    // for it. Broadcast replies (gratuitous ARP) have no single peer.
    const peer = dstMac && dstMac !== 'ff:ff:ff:ff:ff:ff' ? macToIp.get(dstMac) : null;
    if (!peer || peer === sender) return null;
    return { at, bytes, src: sender, dst: peer, protocol: 'arp', srcMac, dstMac };
  }

  return null;
}

function protocolOf(description, ethertype) {
  const d = description.toLowerCase();
  if (d.startsWith('tcp')) return 'tcp';
  if (d.startsWith('udp')) return 'udp';
  if (d.startsWith('icmp6') || d.startsWith('icmpv6')) return 'icmp6';
  if (d.startsWith('icmp')) return 'icmp';
  if (d.startsWith('igmp')) return 'igmp';
  if (d.includes('hbh') || d.includes('mld')) return 'mld';
  if (d.startsWith('gre')) return 'gre';
  if (d.startsWith('esp') || d.startsWith('ah ')) return 'ipsec';
  const proto = d.match(/^ip-proto-(\d+)/);
  if (proto) return `ip-proto-${proto[1]}`;
  return ethertype.includes('6') ? 'ip6' : 'other';
}

/**
 * `192.168.1.5.443` -> {address: '192.168.1.5', port: 443}
 * `fe80::1.5353`    -> {address: 'fe80::1', port: 5353}
 * Only splits when the protocol actually has ports, otherwise the last octet
 * of a bare IPv4 address would be read as one.
 */
function splitAddress(token, hasPorts) {
  const clean = token.replace(/,$/, '');
  if (!hasPorts) return { address: clean || null, port: null };
  const dot = clean.lastIndexOf('.');
  if (dot === -1) return { address: clean || null, port: null };
  const tail = clean.slice(dot + 1);
  if (!/^\d+$/.test(tail)) return { address: clean, port: null };
  const head = clean.slice(0, dot);
  if (!head) return { address: clean, port: null };
  const port = Number(tail);
  return { address: head, port: port >= 0 && port <= 65535 ? port : null };
}
