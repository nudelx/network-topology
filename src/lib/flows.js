/**
 * Traffic-flow model: classify observed packets, aggregate them into flows over
 * a rolling time window, and turn the result into the graph the web UI draws.
 *
 * Deliberately free of Node built-ins. The HTTP server serves this exact file
 * to the browser as /shared/flows.js, so the terminal table and the web map are
 * built from one implementation — the same arrangement topology.js uses.
 *
 * A note on honesty, since this is the part of the app most likely to mislead:
 * a capture on a switched network sees this machine's own traffic plus every
 * broadcast and multicast frame, and nothing else. Two other devices talking
 * unicast to each other are invisible from here. The snapshot carries
 * `vantage` so the UI can say so rather than implying it saw everything.
 */

import { CATEGORIES, serviceName } from './classify.js';
import { normalizeMac, isGroupMac } from './mac.js';

/* ------------------------------------------------------------- traffic class */

export const TRAFFIC_CLASSES = {
  web: { label: 'Web / TLS', order: 0 },
  dns: { label: 'DNS', order: 1 },
  discovery: { label: 'Discovery', order: 2 },
  file: { label: 'File sharing', order: 3 },
  remote: { label: 'Remote access', order: 4 },
  media: { label: 'Media', order: 5 },
  icmp: { label: 'ICMP', order: 6 },
  other: { label: 'Other', order: 7 },
};

export const CLASS_ORDER = Object.entries(TRAFFIC_CLASSES)
  .sort((a, b) => a[1].order - b[1].order)
  .map(([key]) => key);

// Ports that name a class outright. Chosen so an edge's colour says something
// true about what the two ends are doing, not just which transport they used.
const PORT_CLASS = new Map([
  [80, 'web'], [443, 'web'], [8080, 'web'], [8443, 'web'], [8000, 'web'],
  [8888, 'web'], [3000, 'web'], [4173, 'web'], [8006, 'web'],
  [53, 'dns'], [853, 'dns'], [5353, 'discovery'],
  [67, 'discovery'], [68, 'discovery'], [546, 'discovery'], [547, 'discovery'],
  [1900, 'discovery'], [3702, 'discovery'], [5355, 'discovery'],
  [137, 'discovery'], [138, 'discovery'], [5350, 'discovery'], [5351, 'discovery'],
  [139, 'file'], [445, 'file'], [2049, 'file'], [548, 'file'],
  [20, 'file'], [21, 'file'], [873, 'file'], [111, 'file'],
  [22, 'remote'], [23, 'remote'], [3389, 'remote'], [5900, 'remote'], [5901, 'remote'],
  [554, 'media'], [1400, 'media'], [3689, 'media'], [5000, 'media'], [7000, 'media'],
  [8009, 'media'], [8060, 'media'], [32400, 'media'], [1935, 'media'], [5228, 'media'],
]);

/**
 * Which of the two ports names the service.
 *
 * A port this module recognises outright beats one that is merely privileged:
 * for 5 -> 443, the minimum would be 5 and the conversation would be filed as
 * "other" rather than as web traffic. Only when neither or both are recognised
 * does the lower number become the conventional answer.
 */
export function servicePort(srcPort, dstPort) {
  if (srcPort == null) return dstPort ?? null;
  if (dstPort == null) return srcPort;

  const namedSrc = PORT_CLASS.has(srcPort);
  const namedDst = PORT_CLASS.has(dstPort);
  if (namedDst && !namedSrc) return dstPort;
  if (namedSrc && !namedDst) return srcPort;

  const lowSrc = srcPort < 1024;
  const lowDst = dstPort < 1024;
  if (lowDst && !lowSrc) return dstPort;
  if (lowSrc && !lowDst) return srcPort;

  return Math.min(srcPort, dstPort);
}

/** @returns {string} a key of TRAFFIC_CLASSES */
export function classifyTraffic({ protocol, srcPort, dstPort, dst } = {}) {
  if (protocol === 'arp') return 'discovery';
  if (protocol === 'igmp' || protocol === 'mld') return 'discovery';
  if (protocol === 'icmp' || protocol === 'icmp6') return 'icmp';

  const port = servicePort(srcPort ?? null, dstPort ?? null);
  const byPort = port != null ? PORT_CLASS.get(port) : null;
  if (byPort) return byPort;

  // Unlabelled multicast is device chatter of some kind, even when the port is
  // one we do not recognise.
  if (dst && (isMulticast(dst) || isBroadcast(dst))) return 'discovery';
  return 'other';
}

export function portLabel(port, protocol) {
  if (port == null) return protocol ? protocol.toUpperCase() : '—';
  const name = serviceName(port, null);
  return name.startsWith('tcp/') ? `${protocol || 'tcp'}/${port}` : name;
}

/* ----------------------------------------------------------------- addresses */

export function isMulticast(ip) {
  if (ip.includes(':')) return /^ff/i.test(ip);
  const first = Number(ip.split('.')[0]);
  return first >= 224 && first <= 239;
}

export function isBroadcast(ip) {
  return ip === '255.255.255.255' || ip.endsWith('.255');
}

export function isLinkLocal(ip) {
  return ip.includes(':') ? /^fe[89ab]/i.test(ip) : ip.startsWith('169.254.');
}

export function ipSortKey(ip) {
  if (ip.includes(':')) return `z${ip}`;
  return ip
    .split('.')
    .map((p) => String(Number(p)).padStart(3, '0'))
    .join('');
}

/**
 * Minimal CIDR containment. net.js has a richer version, but that module needs
 * node:os and node:child_process and so cannot be served to the browser, and
 * this file must run in both.
 */
export function cidrMatcher(cidrs = []) {
  const ranges = [];
  for (const cidr of cidrs) {
    const [addr, bits] = String(cidr).split('/');
    const prefix = Number(bits);
    if (!addr || !Number.isFinite(prefix) || addr.includes(':')) continue;
    const int = ipToInt(addr);
    if (int == null) continue;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    ranges.push([(int & mask) >>> 0, mask]);
  }
  return (ip) => {
    const int = ipToInt(ip);
    if (int == null) return false;
    return ranges.some(([network, mask]) => (int & mask) >>> 0 === network);
  };
}

function ipToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const byte = Number(part);
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) return null;
    n = n * 256 + byte;
  }
  return n >>> 0;
}

/* --------------------------------------------------------------- time series */

/**
 * Fixed-size ring of per-bucket byte counts. Buckets skipped because nothing
 * was seen are zeroed on the next write, so a quiet period reads as quiet
 * rather than as stale data.
 */
class Ring {
  constructor(size) {
    this.size = size;
    this.buf = new Float64Array(size);
    this.last = null;
  }

  advance(bucket) {
    if (this.last === null) {
      this.last = bucket;
      return;
    }
    if (bucket <= this.last) return;
    const gap = Math.min(bucket - this.last, this.size);
    for (let i = 1; i <= gap; i++) this.buf[(this.last + i) % this.size] = 0;
    this.last = bucket;
  }

  add(bucket, value) {
    this.advance(bucket);
    if (this.last - bucket >= this.size) return; // older than the window
    this.buf[bucket % this.size] += value;
  }

  read(current) {
    this.advance(current);
    const out = new Array(this.size);
    for (let i = 0; i < this.size; i++) {
      // Rounded on the way out: these are counts, and a float that picked up a
      // fraction would serialise as 20 characters in every snapshot frame.
      out[i] = Math.round(this.buf[(current - this.size + 1 + i + this.size * 2) % this.size]);
    }
    return out;
  }
}

/* ------------------------------------------------------------------ counters */

function bump(map, key, bytes, packets) {
  const entry = map.get(key);
  if (entry) {
    entry.bytes += bytes;
    entry.packets += packets;
  } else {
    map.set(key, { bytes, packets });
  }
}

function topOf(map, limit, extra = () => ({})) {
  return [...map.entries()]
    .sort((a, b) => b[1].bytes - a[1].bytes || b[1].packets - a[1].packets)
    .slice(0, limit)
    .map(([key, value]) => ({ key, bytes: value.bytes, packets: value.packets, ...extra(key, value) }));
}

/* ---------------------------------------------------------------- flow table */

export class FlowTable {
  /**
   * @param {object} options
   * @param {number} options.bucketMs      series resolution (default 1s)
   * @param {number} options.windowBuckets how much history to keep (default 90)
   * @param {number} options.maxFlows      hard cap; least-recently-seen evicted
   * @param {string[]} options.selfIps     addresses of this machine
   * @param {string[]} options.localCidrs  subnets counted as "on the LAN"
   */
  constructor({
    bucketMs = 1000,
    windowBuckets = 90,
    maxFlows = 4000,
    maxEndpoints = 3000,
    selfIps = [],
    localCidrs = [],
  } = {}) {
    this.bucketMs = bucketMs;
    this.windowBuckets = windowBuckets;
    this.maxFlows = maxFlows;
    this.maxEndpoints = maxEndpoints;
    this.selfIps = new Set(selfIps);
    this.isLocal = cidrMatcher(localCidrs);

    this.flows = new Map();
    this.endpoints = new Map();
    this.classes = new Map();
    this.series = new Ring(windowBuckets);

    this.startedAt = null;
    this.lastAt = null;
    this.packets = 0;
    this.bytes = 0;
    this.dropped = 0; // packets discarded by eviction pressure
  }

  kindOf(ip) {
    if (this.selfIps.has(ip)) return 'self';
    if (isBroadcast(ip)) return 'broadcast';
    if (isMulticast(ip)) return 'multicast';
    if (isLinkLocal(ip)) return 'local';
    if (this.isLocal(ip)) return 'local';
    return 'internet';
  }

  endpoint(ip) {
    let entry = this.endpoints.get(ip);
    if (!entry) {
      entry = {
        ip,
        kind: this.kindOf(ip),
        sentBytes: 0,
        recvBytes: 0,
        sentPackets: 0,
        recvPackets: 0,
        peers: new Set(),
        classes: new Map(),
        ports: new Map(),
        processes: new Set(),
        macs: new Set(),
        firstSeen: null,
        lastSeen: null,
        // Kept apart rather than as one total, so "top senders" and "top
        // consumers" are answerable over time and not just in aggregate.
        sentRing: new Ring(this.windowBuckets),
        recvRing: new Ring(this.windowBuckets),
      };
      if (this.endpoints.size >= this.maxEndpoints) this.evictEndpoints();
      this.endpoints.set(ip, entry);
    }
    return entry;
  }

  /**
   * Record the hardware address seen carrying traffic for `ip`.
   *
   * Only ever for an address on this segment. A packet to or from the Internet
   * carries the *router's* MAC in the frame, so attributing it to the remote
   * address would confidently label every external host as the gateway. Group
   * MACs name a multicast or broadcast set rather than a device, so they are
   * excluded too.
   */
  noteMac(ip, mac) {
    if (!mac) return;
    const kind = this.kindOf(ip);
    if (kind !== 'self' && kind !== 'local') return;
    const norm = normalizeMac(mac);
    if (!norm || isGroupMac(norm)) return;
    const entry = this.endpoints.get(ip);
    // A MAC does not change under an address; a handful is already suspicious,
    // so the set is capped rather than allowed to grow on spoofed traffic.
    if (entry && entry.macs.size < 4) entry.macs.add(norm);
  }

  /**
   * @param {object} packet {at, src, dst, srcPort, dstPort, protocol, bytes, process, srcMac, dstMac}
   */
  add(packet) {
    const { src, dst } = packet;
    if (!src || !dst || src === dst) return;

    const at = packet.at || this.lastAt || 0;
    const bytes = Number(packet.bytes) || 0;
    const count = Number(packet.packets) || 1;
    const bucket = Math.floor(at / this.bucketMs);
    const cls = classifyTraffic(packet);
    const port = servicePort(packet.srcPort ?? null, packet.dstPort ?? null);

    if (this.startedAt === null) this.startedAt = at;
    this.lastAt = Math.max(this.lastAt ?? 0, at);
    this.packets += count;
    this.bytes += bytes;
    this.series.add(bucket, bytes);
    bump(this.classes, cls, bytes, count);

    // Canonical undirected key, so A→B and B→A are one edge with two counters.
    const forward = ipSortKey(src) <= ipSortKey(dst);
    const a = forward ? src : dst;
    const b = forward ? dst : src;
    const key = `${a}|${b}`;

    let flow = this.flows.get(key);
    if (!flow) {
      if (this.flows.size >= this.maxFlows) this.evict();
      flow = {
        key,
        a,
        b,
        aKind: this.kindOf(a),
        bKind: this.kindOf(b),
        fwd: { bytes: 0, packets: 0 },
        rev: { bytes: 0, packets: 0 },
        classes: new Map(),
        ports: new Map(),
        protocols: new Set(),
        processes: new Set(),
        firstSeen: at,
        lastSeen: at,
        ring: new Ring(this.windowBuckets),
      };
      this.flows.set(key, flow);
    }

    const dir = forward ? flow.fwd : flow.rev;
    dir.bytes += bytes;
    dir.packets += count;
    flow.lastSeen = Math.max(flow.lastSeen, at);
    flow.ring.add(bucket, bytes);
    flow.protocols.add(packet.protocol || 'other');
    bump(flow.classes, cls, bytes, count);
    if (port != null) bump(flow.ports, port, bytes, count);
    if (packet.process) flow.processes.add(packet.process);

    for (const [ip, peer, sending] of [[src, dst, true], [dst, src, false]]) {
      const entry = this.endpoint(ip);
      if (entry.firstSeen === null) entry.firstSeen = at;
      entry.lastSeen = at;
      entry.peers.add(peer);
      bump(entry.classes, cls, bytes, count);
      if (port != null) bump(entry.ports, port, bytes, count);
      if (packet.process) entry.processes.add(packet.process);
      if (sending) {
        entry.sentBytes += bytes;
        entry.sentPackets += count;
        entry.sentRing.add(bucket, bytes);
      } else {
        entry.recvBytes += bytes;
        entry.recvPackets += count;
        entry.recvRing.add(bucket, bytes);
      }
    }

    this.noteMac(src, packet.srcMac);
    this.noteMac(dst, packet.dstMac);
  }

  /**
   * Endpoints hold two ring buffers each, so an unbounded table is real memory.
   * A browsing session touches hundreds of CDN addresses, and the coldest are
   * the least interesting, so they go first.
   */
  evictEndpoints() {
    const victims = [...this.endpoints.values()]
      .sort((x, y) => (x.lastSeen ?? 0) - (y.lastSeen ?? 0))
      .slice(0, Math.max(1, Math.floor(this.maxEndpoints / 10)));
    for (const entry of victims) {
      this.evictedEndpoints = (this.evictedEndpoints || 0) + 1;
      this.endpoints.delete(entry.ip);
    }
  }

  /** Drop the coldest tenth of the table so a busy link cannot grow it forever. */
  evict() {
    const victims = [...this.flows.values()]
      .sort((x, y) => x.lastSeen - y.lastSeen)
      .slice(0, Math.max(1, Math.floor(this.maxFlows / 10)));
    for (const flow of victims) {
      this.dropped += flow.fwd.packets + flow.rev.packets;
      this.flows.delete(flow.key);
    }
  }

  /**
   * A plain-JSON view of the table. Series are attached only to the busiest
   * rows: 4000 flows x 90 buckets would dwarf everything else on the wire.
   */
  snapshot({
    now = this.lastAt || 0,
    maxFlows = 400,
    maxEndpoints = 300,
    seriesFor = 80,
    vantage = null,
  } = {}) {
    const bucket = Math.floor(now / this.bucketMs);

    const flows = [...this.flows.values()]
      .map((flow) => ({
        flow,
        bytes: flow.fwd.bytes + flow.rev.bytes,
        packets: flow.fwd.packets + flow.rev.packets,
      }))
      .sort((x, y) => y.bytes - x.bytes || y.packets - x.packets);

    const endpoints = [...this.endpoints.values()]
      .map((entry) => ({ entry, bytes: entry.sentBytes + entry.recvBytes }))
      .sort((x, y) => y.bytes - x.bytes);

    return {
      window: {
        bucketMs: this.bucketMs,
        buckets: this.windowBuckets,
        startedAt: this.startedAt,
        lastAt: this.lastAt,
        now,
      },
      vantage,
      totals: {
        bytes: this.bytes,
        packets: this.packets,
        flows: this.flows.size,
        endpoints: this.endpoints.size,
        droppedPackets: this.dropped,
      },
      series: this.series.read(bucket),
      classes: topOf(this.classes, CLASS_ORDER.length, (key) => ({
        label: TRAFFIC_CLASSES[key]?.label || key,
      })),
      endpoints: endpoints.slice(0, maxEndpoints).map(({ entry }, index) => ({
        ip: entry.ip,
        kind: entry.kind,
        sentBytes: entry.sentBytes,
        recvBytes: entry.recvBytes,
        sentPackets: entry.sentPackets,
        recvPackets: entry.recvPackets,
        peerCount: entry.peers.size,
        firstSeen: entry.firstSeen,
        lastSeen: entry.lastSeen,
        processes: [...entry.processes].slice(0, 8),
        macs: [...entry.macs],
        classes: topOf(entry.classes, 4),
        ports: topOf(entry.ports, 6, (port) => ({ port, label: portLabel(port) })),
        sentSeries: index < seriesFor ? entry.sentRing.read(bucket) : null,
        recvSeries: index < seriesFor ? entry.recvRing.read(bucket) : null,
      })),
      flows: flows.slice(0, maxFlows).map(({ flow, bytes, packets }, index) => ({
        key: flow.key,
        a: flow.a,
        b: flow.b,
        aKind: flow.aKind,
        bKind: flow.bKind,
        bytes,
        packets,
        aToB: { ...flow.fwd },
        bToA: { ...flow.rev },
        protocols: [...flow.protocols],
        processes: [...flow.processes].slice(0, 8),
        firstSeen: flow.firstSeen,
        lastSeen: flow.lastSeen,
        classes: topOf(flow.classes, CLASS_ORDER.length, (key) => ({
          label: TRAFFIC_CLASSES[key]?.label || key,
        })),
        ports: topOf(flow.ports, 8, (port) => ({
          port,
          label: portLabel(port, flow.protocols.values().next().value),
        })),
        series: index < seriesFor ? flow.ring.read(bucket) : null,
      })),
      truncated: {
        flows: Math.max(0, flows.length - maxFlows),
        endpoints: Math.max(0, endpoints.length - maxEndpoints),
      },
      evicted: {
        flows: this.dropped,
        endpoints: this.evictedEndpoints || 0,
      },
    };
  }
}

/* ----------------------------------------------------------------- identity */

/**
 * Index a scan model for endpoint lookup. Three keys, because a capture and a
 * scan do not always see a device the same way: the scan knows it by the
 * address it answered on, while the wire shows a hardware address that survives
 * a DHCP lease change and is shared by the device's IPv4, IPv6 and link-local
 * addresses alike.
 */
export function createIdentityIndex(model) {
  const byIp = new Map();
  const byMac = new Map();
  const byName = new Map();

  for (const device of model?.devices || []) {
    if (device.ip) byIp.set(device.ip, device);

    const mac = normalizeMac(device.mac);
    if (mac && !isGroupMac(mac)) byMac.set(mac, device);

    for (const name of [device.hostname, ...(device.hostnames || [])]) {
      const key = nameKey(name);
      // First writer wins: devices are in address order, so a duplicated name
      // resolves to the lowest address rather than an arbitrary one.
      if (key && !byName.has(key)) byName.set(key, device);
    }
  }

  return { byIp, byMac, byName, devices: model?.devices?.length || 0 };
}

/** Hostnames are compared case-insensitively and without the mDNS suffix. */
export function nameKey(name) {
  if (!name) return null;
  return String(name).trim().toLowerCase().replace(/\.$/, '').replace(/\.local$/, '') || null;
}

function deviceName(device) {
  return device.hostname ? stripLocal(device.hostname) : device.ip;
}

/**
 * Tie one traffic endpoint to a scanned device.
 *
 * Order of trust: the hardware address seen carrying the traffic, then the
 * address itself, then the name. MAC wins because it was observed now, whereas
 * an address only says where the device was when the scan ran. Every match
 * records how it was made, the way classify.js records why it picked a type.
 *
 * @returns {{device: object|null, via: 'mac'|'ip'|'name'|null, reasons: string[]}}
 */
export function identifyEndpoint(endpoint, index) {
  const reasons = [];
  let device = null;
  let via = null;

  const observed = (endpoint.macs || []).map(normalizeMac).filter(Boolean);

  for (const mac of observed) {
    const hit = index.byMac.get(mac);
    if (hit) {
      device = hit;
      via = 'mac';
      reasons.push(`hardware address ${mac} seen on the wire matches this device in the scan`);
      break;
    }
  }

  const atAddress = endpoint.ip ? index.byIp.get(endpoint.ip) : null;
  if (!device && atAddress) {
    const scannedMac = normalizeMac(atAddress.mac);
    if (scannedMac && observed.length && !observed.includes(scannedMac)) {
      // The address matches, but the hardware behind it does not. Naming this
      // endpoint after the scan's device would be a confident lie: a DHCP lease
      // has moved, or the scan is stale. Better to leave it unidentified.
      reasons.push(
        `${endpoint.ip} was ${deviceName(atAddress)} in the last scan, but the hardware address on the wire `
        + `(${observed[0]}) is a different device — the address has changed hands`,
      );
    } else {
      device = atAddress;
      via = 'ip';
      reasons.push(`${endpoint.ip} matches a scanned device`);
    }
  } else if (device && atAddress && atAddress !== device) {
    reasons.push(`the last scan saw ${deviceName(atAddress)} at ${endpoint.ip}, so that address has changed hands since`);
  } else if (device && via === 'mac' && endpoint.ip && device.ip !== endpoint.ip) {
    reasons.push(`the scan knew this device as ${device.ip}`);
  }

  if (!device && endpoint.hostname) {
    const hit = index.byName.get(nameKey(endpoint.hostname));
    if (hit) {
      device = hit;
      via = 'name';
      reasons.push(`name ${endpoint.hostname} matches a scanned device`);
    }
  }

  if (!device) {
    if (endpoint.kind === 'self') reasons.push('this machine — the capture point');
    else if (endpoint.kind === 'multicast' || endpoint.kind === 'broadcast') {
      reasons.push('a group address, not a single device');
    } else {
      reasons.push(observed.length
        ? 'seen on the wire but not in the last scan — run a scan to identify it'
        : 'not in the last scan');
    }
  }

  return { device, via, reasons };
}

/* ------------------------------------------------------------- graph builder */

const WELL_KNOWN_GROUPS = new Map([
  ['224.0.0.251', { label: 'mDNS multicast', icon: '📢' }],
  ['ff02::fb', { label: 'mDNS multicast', icon: '📢' }],
  ['239.255.255.250', { label: 'SSDP multicast', icon: '📢' }],
  ['224.0.0.1', { label: 'All hosts multicast', icon: '📢' }],
  ['224.0.0.2', { label: 'All routers multicast', icon: '📢' }],
  ['224.0.0.22', { label: 'IGMP multicast', icon: '📢' }],
  ['224.0.0.252', { label: 'LLMNR multicast', icon: '📢' }],
  ['255.255.255.255', { label: 'Broadcast', icon: '📣' }],
]);

// Lower rank == closer to home. Drives edge orientation only.
const KIND_RANK = { self: 0, local: 1, multicast: 2, broadcast: 2, internet: 3 };

function kindRank(kind) {
  return KIND_RANK[kind] ?? 2;
}

const KIND_ICON = {
  self: '🖥️',
  internet: '🌍',
  multicast: '📢',
  broadcast: '📣',
  local: '❔',
};

function stripLocal(name) {
  return String(name || '').replace(/\.local$/i, '');
}

function endpointLabel(ip, kind, device, vendor) {
  const known = WELL_KNOWN_GROUPS.get(ip.toLowerCase());
  if (known) return known.label;
  if (device?.hostname) return stripLocal(device.hostname);
  if (device?.vendor && !/randomized/i.test(device.vendor)) return `${device.vendor} device`;
  if (kind === 'broadcast') return 'Broadcast';
  if (ip.endsWith('.255')) return 'Subnet broadcast';
  // Not in the scan, but its MAC was on the wire, and an OUI names a maker.
  if (vendor && !/randomized/i.test(vendor)) return `${vendor} device`;
  return ip;
}

function endpointIcon(ip, kind, device) {
  const known = WELL_KNOWN_GROUPS.get(ip.toLowerCase());
  if (known) return known.icon;
  if (device) return CATEGORIES[device.category]?.icon || CATEGORIES.unknown.icon;
  return KIND_ICON[kind] || KIND_ICON.local;
}

function mergeCounters(target, additions) {
  for (const item of additions || []) {
    const entry = target.get(item.key);
    if (entry) {
      entry.bytes += item.bytes;
      entry.packets += item.packets;
    } else {
      target.set(item.key, { bytes: item.bytes, packets: item.packets, label: item.label, port: item.port });
    }
  }
}

/** Elementwise sum of two series, either of which may be absent. */
export function addSeries(a, b) {
  if (!a) return b ? b.slice() : null;
  if (!b) return a.slice();
  const out = new Array(Math.max(a.length, b.length));
  for (let i = 0; i < out.length; i++) out[i] = (a[i] || 0) + (b[i] || 0);
  return out;
}

function sumSeries(target, series) {
  if (!series) return target;
  if (!target) return series.slice();
  for (let i = 0; i < Math.min(target.length, series.length); i++) target[i] += series[i];
  return target;
}

/**
 * Snapshot + scan model -> the node/edge graph the traffic view renders.
 *
 * Endpoints inherit their identity from the scan when the scan happens to know
 * the address; the traffic view never invents a device the scan did not see, it
 * just shows the bare IP instead.
 *
 * @param {object} args
 * @param {object} args.snapshot      FlowTable#snapshot output
 * @param {object|null} args.model    the topology scan model, for identity
 * @param {object} args.options       {groupInternet, classFilter, query, minBytes}
 */
export function buildFlowGraph({ snapshot, model = null, options = {} } = {}) {
  const {
    groupInternet = true,
    classFilter = null,
    query = '',
    minBytes = 0,
  } = options;

  if (!snapshot) return { nodes: [], edges: [], classes: [], stats: null };

  const devices = new Map();
  for (const device of model?.devices || []) devices.set(device.ip, device);

  const cats = classFilter && classFilter.size ? classFilter : null;
  const q = query.trim().toLowerCase();

  // Which node id each raw address belongs to. Grouping the Internet side keeps
  // a browser session with 200 CDN endpoints from burying the LAN.
  const nodeIdFor = new Map();
  const nodes = new Map();

  const ensureNode = (id, seed) => {
    let node = nodes.get(id);
    if (!node) {
      node = {
        id,
        ip: seed.ip,
        kind: seed.kind,
        label: seed.label,
        sublabel: seed.sublabel,
        icon: seed.icon,
        category: seed.category || null,
        device: seed.device || null,
        mac: seed.mac || null,
        vendor: seed.vendor || null,
        identifiedVia: seed.identifiedVia || null,
        identityReasons: seed.identityReasons || [],
        macs: new Set(),
        addresses: new Set(),
        sentBytes: 0,
        recvBytes: 0,
        sentPackets: 0,
        recvPackets: 0,
        peerCount: 0,
        members: [],
        processes: new Set(),
        classes: new Map(),
        ports: new Map(),
        sentSeries: null,
        recvSeries: null,
        lastSeen: 0,
      };
      nodes.set(id, node);
    }
    return node;
  };

  const selfLabel = model?.meta?.host?.hostname
    ? stripLocal(model.meta.host.hostname)
    : 'This machine';
  const index = createIdentityIndex(model);
  const macVendors = snapshot.macVendors || {};

  for (const endpoint of snapshot.endpoints || []) {
    const identity = identifyEndpoint(endpoint, index);
    const device = identity.device;
    const observedMac = (endpoint.macs || [])[0] || null;
    const vendor = device?.vendor || (observedMac ? macVendors[observedMac] : null) || null;

    // What makes two addresses one node. This machine usually holds several (a
    // NIC, a VM bridge, a tunnel); so does any device with IPv4, IPv6 and a
    // link-local address — identifying it by MAC is what lets those collapse
    // into the one device they actually are instead of three strangers.
    const wellKnown = WELL_KNOWN_GROUPS.get(String(endpoint.ip).toLowerCase());
    let id;
    if (endpoint.kind === 'self') id = 'self';
    else if (groupInternet && endpoint.kind === 'internet') id = 'internet';
    else if (device) id = `dev:${device.ip}`;
    // 224.0.0.251 and ff02::fb are the same mDNS group wearing two addresses.
    else if (wellKnown) id = `group:${wellKnown.label}`;
    else id = endpoint.ip;

    nodeIdFor.set(endpoint.ip, id);
    let seed;
    if (id === 'self') {
      seed = {
        ip: endpoint.ip,
        kind: 'self',
        label: selfLabel,
        sublabel: endpoint.ip,
        icon: '🖥️',
        category: device?.category || 'computer',
        device,
        mac: device?.mac || observedMac,
        vendor,
        identifiedVia: identity.via,
        identityReasons: identity.reasons,
      };
    } else if (id === 'internet') {
      seed = { ip: null, kind: 'internet', label: 'Internet', sublabel: 'grouped endpoints', icon: '🌍' };
    } else {
      seed = {
        ip: endpoint.ip,
        kind: endpoint.kind,
        label: endpointLabel(endpoint.ip, endpoint.kind, device, vendor),
        sublabel: endpoint.ip,
        icon: endpointIcon(endpoint.ip, endpoint.kind, device),
        category: device?.category || null,
        device,
        mac: device?.mac || observedMac,
        vendor,
        identifiedVia: identity.via,
        identityReasons: identity.reasons,
      };
    }
    const node = ensureNode(id, seed);
    for (const mac of endpoint.macs || []) node.macs.add(mac);
    if (endpoint.ip) node.addresses.add(endpoint.ip);

    node.sentBytes += endpoint.sentBytes;
    node.recvBytes += endpoint.recvBytes;
    node.sentPackets += endpoint.sentPackets;
    node.recvPackets += endpoint.recvPackets;
    node.peerCount += endpoint.peerCount;
    node.lastSeen = Math.max(node.lastSeen, endpoint.lastSeen || 0);
    node.sentSeries = sumSeries(node.sentSeries, endpoint.sentSeries);
    node.recvSeries = sumSeries(node.recvSeries, endpoint.recvSeries);
    for (const name of endpoint.processes || []) node.processes.add(name);
    mergeCounters(node.classes, endpoint.classes);
    mergeCounters(node.ports, endpoint.ports);
    node.members.push({ ip: endpoint.ip, bytes: endpoint.sentBytes + endpoint.recvBytes });
    if (id !== 'internet' && node.members.length > 1) {
      node.sublabel = `${node.members.length} addresses`;
    }
  }

  const edges = new Map();
  for (const flow of snapshot.flows || []) {
    const classes = cats ? (flow.classes || []).filter((c) => cats.has(c.key)) : flow.classes;
    if (cats && !classes.length) continue;

    const rawSource = nodeIdFor.get(flow.a);
    const rawTarget = nodeIdFor.get(flow.b);
    if (!rawSource || !rawTarget || rawSource === rawTarget) continue;

    // Point the edge outward from the most local end, so "phone → Internet"
    // rather than whichever address happened to sort first.
    const outward = kindRank(nodes.get(rawSource)?.kind) <= kindRank(nodes.get(rawTarget)?.kind);
    const sourceId = outward ? rawSource : rawTarget;
    const targetId = outward ? rawTarget : rawSource;
    const id = `${sourceId} ↔ ${targetId}`;
    let edge = edges.get(id);
    if (!edge) {
      edge = {
        id,
        source: sourceId,
        target: targetId,
        bytes: 0,
        packets: 0,
        forwardBytes: 0,
        reverseBytes: 0,
        classes: new Map(),
        ports: new Map(),
        protocols: new Set(),
        processes: new Set(),
        flowCount: 0,
        firstSeen: flow.firstSeen,
        lastSeen: flow.lastSeen,
        series: null,
        members: [],
      };
      edges.set(id, edge);
    }

    // Orientation is per-edge, not per-flow: a grouped Internet node merges
    // flows whose canonical a/b order differs from the edge's.
    const aIsSource = nodeIdFor.get(flow.a) === edge.source;
    edge.bytes += flow.bytes;
    edge.packets += flow.packets;
    edge.forwardBytes += aIsSource ? flow.aToB.bytes : flow.bToA.bytes;
    edge.reverseBytes += aIsSource ? flow.bToA.bytes : flow.aToB.bytes;
    edge.flowCount += 1;
    edge.firstSeen = Math.min(edge.firstSeen, flow.firstSeen);
    edge.lastSeen = Math.max(edge.lastSeen, flow.lastSeen);
    edge.series = sumSeries(edge.series, flow.series);
    for (const p of flow.protocols || []) edge.protocols.add(p);
    for (const name of flow.processes || []) edge.processes.add(name);
    mergeCounters(edge.classes, classes);
    mergeCounters(edge.ports, flow.ports);
    if (edge.members.length < 40) edge.members.push({ a: flow.a, b: flow.b, bytes: flow.bytes });
  }

  const finish = (map, limit) => [...map.entries()]
    .map(([key, value]) => ({ key, ...value }))
    .sort((x, y) => y.bytes - x.bytes)
    .slice(0, limit);

  let edgeList = [...edges.values()]
    .filter((edge) => edge.bytes >= minBytes)
    .map((edge) => ({
      ...edge,
      classes: finish(edge.classes, CLASS_ORDER.length),
      ports: finish(edge.ports, 8),
      protocols: [...edge.protocols],
      processes: [...edge.processes],
    }))
    .sort((x, y) => y.bytes - x.bytes);

  for (const edge of edgeList) edge.dominant = edge.classes[0]?.key || 'other';

  let nodeList = [...nodes.values()].map((node) => ({
    ...node,
    bytes: node.sentBytes + node.recvBytes,
    packets: node.sentPackets + node.recvPackets,
    // Sparklines want one line; the heatmap wants the two directions apart.
    series: addSeries(node.sentSeries, node.recvSeries),
    classes: finish(node.classes, 4),
    ports: finish(node.ports, 6),
    processes: [...node.processes],
    macs: [...node.macs],
    addresses: [...node.addresses],
    memberCount: node.members.length,
  }));

  // A search prunes to matching nodes and everything they talk to, so a match
  // still shows its context rather than a lone disconnected dot.
  if (q) {
    const matches = new Set(
      nodeList
        .filter((node) => nodeHaystack(node).includes(q))
        .map((node) => node.id),
    );
    const keep = new Set(matches);
    for (const edge of edgeList) {
      if (matches.has(edge.source)) keep.add(edge.target);
      if (matches.has(edge.target)) keep.add(edge.source);
    }
    nodeList = nodeList.map((node) => ({ ...node, matched: matches.has(node.id) })).filter((node) => keep.has(node.id));
    edgeList = edgeList.filter((edge) => keep.has(edge.source) && keep.has(edge.target));
  }

  // Drop endpoints left with nothing to show after filtering.
  if (cats || minBytes > 0) {
    const connected = new Set();
    for (const edge of edgeList) {
      connected.add(edge.source);
      connected.add(edge.target);
    }
    nodeList = nodeList.filter((node) => connected.has(node.id));
  }

  // Under a class filter a node must be sized by the traffic still on screen.
  // Sizing it by its untouched total would draw a mostly-web device large in a
  // file-sharing-only view, which is exactly the wrong thing for a map whose
  // point is proportion.
  if (cats) {
    const sums = new Map();
    for (const edge of edgeList) {
      for (const id of [edge.source, edge.target]) {
        const entry = sums.get(id) || { bytes: 0, packets: 0 };
        entry.bytes += edge.bytes;
        entry.packets += edge.packets;
        sums.set(id, entry);
      }
    }
    nodeList = nodeList.map((node) => {
      const entry = sums.get(node.id);
      return {
        ...node,
        filtered: true,
        totalBytes: node.bytes,
        bytes: entry ? entry.bytes : 0,
        packets: entry ? entry.packets : 0,
      };
    });
  }

  const present = new Set(nodeList.map((node) => node.id));
  edgeList = edgeList.filter((edge) => present.has(edge.source) && present.has(edge.target));

  // Prefer the capture window over first-to-last-packet: a source that samples
  // (the connection poller) would otherwise report a duration much shorter than
  // it actually watched for, inflating every rate derived from it.
  const vantage = snapshot.vantage;
  const captureMs = vantage?.startedAt
    ? Math.max(0, (vantage.stoppedAt || snapshot.window?.now || vantage.startedAt) - vantage.startedAt)
    : 0;
  const elapsedMs = captureMs > 0
    ? captureMs
    : (snapshot.window?.startedAt != null && snapshot.window?.lastAt != null
        ? Math.max(0, snapshot.window.lastAt - snapshot.window.startedAt)
        : 0);

  const unit = snapshot.vantage?.unit === 'connections' ? 'connections' : 'bytes';

  return {
    nodes: nodeList.sort((x, y) => y.bytes - x.bytes),
    edges: edgeList,
    classes: snapshot.classes || [],
    vantage: snapshot.vantage || null,
    unit,
    filtered: Boolean(cats),
    stats: {
      ...snapshot.totals,
      elapsedMs,
      shownNodes: nodeList.length,
      shownEdges: edgeList.length,
      truncated: snapshot.truncated,
      bytesPerSecond: elapsedMs > 0 ? (snapshot.totals?.bytes || 0) / (elapsedMs / 1000) : 0,
    },
    series: snapshot.series || [],
    window: snapshot.window || null,
  };
}

function nodeHaystack(node) {
  const parts = [
    node.label, node.ip, node.kind, node.category, node.mac, node.vendor,
    ...(node.processes || []),
    ...(node.macs || []),
    ...(node.addresses || []),
  ];
  const device = node.device;
  if (device) parts.push(device.mac, device.vendor, device.hostname, device.os, ...(device.hostnames || []));
  for (const port of node.ports || []) parts.push(String(port.port ?? port.key), port.label);
  for (const cls of node.classes || []) parts.push(cls.key, cls.label);
  return parts.filter(Boolean).join(' ').toLowerCase();
}

/* ---------------------------------------------------------------- formatting */

export function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ['kB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function formatRate(bytesPerSecond) {
  const bits = (Number(bytesPerSecond) || 0) * 8;
  if (bits < 1000) return `${Math.round(bits)} bit/s`;
  const units = ['kbit/s', 'Mbit/s', 'Gbit/s'];
  let value = bits / 1000;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function formatCount(n) {
  const value = Number(n) || 0;
  if (value < 1000) return String(value);
  return value.toLocaleString();
}

/**
 * A weight is bytes when a capture measured them and connection counts when the
 * fallback did not. Everything user-facing goes through here so the two can
 * never be confused for one another.
 */
export function formatWeight(value, unit) {
  return unit === 'connections' ? formatCount(value) : formatBytes(value);
}

export function weightNoun(unit, value) {
  if (unit !== 'connections') return 'bytes';
  return value === 1 ? 'connection' : 'connections';
}

// Eight levels of block, so a terminal row carries the same shape the web
// heatmap shades. Shared with the browser like everything else here.
const SPARK_LEVELS = '▁▂▃▄▅▆▇█';

/**
 * A per-second series rendered as blocks, downsampled to `width` columns by
 * taking each group's maximum — a mean would smooth away exactly the bursts
 * the picture is for.
 */
export function sparkText(series, { width = 40, max = null } = {}) {
  const values = series || [];
  if (!values.length) return ' '.repeat(width);
  const groups = new Array(width).fill(0);
  const per = values.length / width;
  for (let i = 0; i < values.length; i++) {
    const slot = Math.min(width - 1, Math.floor(i / per));
    groups[slot] = Math.max(groups[slot], values[i]);
  }
  const peak = max || Math.max(1, ...groups);
  return groups
    .map((value) => {
      if (value <= 0) return ' ';
      // Square-rooted for the same reason the web view is: byte counts are
      // heavy-tailed, and a linear ramp leaves everything but the peak blank.
      const level = Math.min(
        SPARK_LEVELS.length - 1,
        Math.floor(Math.sqrt(value / peak) * (SPARK_LEVELS.length - 1)),
      );
      return SPARK_LEVELS[level];
    })
    .join('');
}

/**
 * How many trailing buckets are worth drawing. A five-second capture into a
 * ninety-second window would otherwise spend most of its width on time that
 * had not happened yet, squeezing the actual data into a corner.
 */
export function visibleBuckets(graph) {
  const total = graph?.window?.buckets || 90;
  const bucketMs = graph?.window?.bucketMs || 1000;
  const elapsed = Math.ceil((graph?.stats?.elapsedMs || 0) / bucketMs);
  return Math.max(8, Math.min(total, elapsed + 1));
}

/** The last `count` entries of a series, padded if it is somehow shorter. */
export function tailOf(series, count) {
  if (!series) return null;
  if (series.length <= count) return series.slice();
  return series.slice(series.length - count);
}

const METRIC_PICK = {
  total: (node) => node.bytes,
  sent: (node) => node.sentBytes,
  received: (node) => node.recvBytes,
};

const METRIC_SERIES = {
  total: (node) => node.series,
  sent: (node) => node.sentSeries,
  received: (node) => node.recvSeries,
};

/**
 * Ranked endpoints with both directions and an activity strip — the terminal
 * form of the heatmap.
 */
export function endpointsToText(graph, { limit = 10, metric = 'total', width = 22, spark = 34 } = {}) {
  const pick = METRIC_PICK[metric] || METRIC_PICK.total;
  const series = METRIC_SERIES[metric] || METRIC_SERIES.total;
  const unit = graph.unit || 'bytes';
  const pad = (value, n) => (String(value).length > n
    ? `${String(value).slice(0, n - 1)}…`
    : String(value).padEnd(n));

  const rows = graph.nodes
    .map((node) => ({ node, weight: pick(node) || 0, series: series(node) }))
    .filter((row) => row.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, limit);

  const lines = [];
  lines.push(
    `${pad('device', width)} ${'sent'.padStart(9)} ${'recv'.padStart(9)}  ${pad('activity', spark)}`,
  );
  lines.push('─'.repeat(width + 9 + 9 + spark + 4));
  if (!rows.length) {
    lines.push(`(nothing ${metric === 'total' ? 'recorded' : metric} in this window)`);
    return lines;
  }

  // One scale across all rows, so the strips are comparable down the column.
  const shown = visibleBuckets(graph);
  const trimmed = rows.map((row) => ({ ...row, series: tailOf(row.series, shown) }));
  const peak = Math.max(1, ...trimmed.flatMap((row) => row.series || [0]));
  for (const row of trimmed) {
    lines.push(
      `${pad(row.node.label, width)} ${formatWeight(row.node.sentBytes, unit).padStart(9)} `
      + `${formatWeight(row.node.recvBytes, unit).padStart(9)}  ${sparkText(row.series, { width: spark, max: peak })}`,
    );
  }
  return lines;
}

/** Terminal table of the busiest edges, used by `topology traffic`. */
export function flowsToText(graph, { limit = 25, width = 22 } = {}) {
  const pad = (s, n) => String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s).padEnd(n);
  const lines = [];
  const label = (id) => graph.nodes.find((node) => node.id === id)?.label || id;
  const unit = graph.unit || 'bytes';
  const byBytes = unit === 'bytes';

  lines.push(
    `${pad('source', width)} ${pad('destination', width)} ${pad('class', 13)} ` +
    `${(byBytes ? 'packets' : 'seen').padStart(9)} ${(byBytes ? 'bytes' : 'conns').padStart(9)} ` +
    `${(byBytes ? 'rate' : '').padStart(11)}`,
  );
  lines.push('─'.repeat(width * 2 + 13 + 9 + 9 + 11 + 5));

  const seconds = Math.max(1, (graph.stats?.elapsedMs || 0) / 1000);
  for (const edge of graph.edges.slice(0, limit)) {
    lines.push(
      `${pad(label(edge.source), width)} ${pad(label(edge.target), width)} ` +
      `${pad(TRAFFIC_CLASSES[edge.dominant]?.label || edge.dominant, 13)} ` +
      `${formatCount(edge.packets).padStart(9)} ${formatWeight(edge.bytes, unit).padStart(9)} ` +
      `${(byBytes ? formatRate(edge.bytes / seconds) : '').padStart(11)}`,
    );
  }
  if (graph.edges.length > limit) {
    lines.push(`… and ${graph.edges.length - limit} more conversations`);
  }
  return lines;
}
