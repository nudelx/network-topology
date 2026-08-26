import dgram from 'node:dgram';
import dns from 'node:dns/promises';

/**
 * Hostname resolution for devices a home/office router does not publish PTR
 * records for — which is most of them. Three sources, cheapest first:
 *
 *   1. unicast reverse DNS  (works when a real DNS server owns the zone)
 *   2. mDNS  (port 5353) — Apple, Sonos, Espressif, printers, Linux w/ Avahi
 *   3. NetBIOS (port 137) — Windows and Samba hosts
 *
 * Both multicast protocols answer plain unicast queries, so we can ask each
 * host directly instead of flooding the segment with broadcasts.
 */

/* ------------------------------------------------------------ DNS wire bits */

function encodeName(name) {
  const parts = name.split('.').filter(Boolean);
  const bufs = [];
  for (const p of parts) {
    const b = Buffer.from(p, 'ascii');
    bufs.push(Buffer.from([b.length]), b);
  }
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let jumped = false;
  let end = offset;
  let guard = 0;

  while (pos < buf.length && guard++ < 128) {
    const len = buf[pos];
    if (len === 0) {
      pos += 1;
      if (!jumped) end = pos;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      const pointer = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) end = pos + 2;
      pos = pointer;
      jumped = true;
      continue;
    }
    labels.push(buf.slice(pos + 1, pos + 1 + len).toString('ascii'));
    pos += 1 + len;
    if (!jumped) end = pos;
  }

  return { name: labels.join('.'), end };
}

function buildQuery(qname, qtype, qclass) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0, 0);       // id 0 is legal for mDNS
  header.writeUInt16BE(0, 2);       // standard query
  header.writeUInt16BE(1, 4);       // qdcount
  const q = encodeName(qname);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(qclass, 2);
  return Buffer.concat([header, q, tail]);
}

function firstPtrAnswer(buf) {
  if (buf.length < 12) return null;
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);
  if (ancount === 0) return null;

  let pos = 12;
  for (let i = 0; i < qdcount; i++) {
    const { end } = readName(buf, pos);
    pos = end + 4;
  }
  for (let i = 0; i < ancount && pos + 10 <= buf.length; i++) {
    const { end } = readName(buf, pos);
    let p = end;
    const type = buf.readUInt16BE(p);
    const rdlength = buf.readUInt16BE(p + 8);
    p += 10;
    if (type === 12) return readName(buf, p).name; // PTR
    pos = p + rdlength;
  }
  return null;
}

function reverseZone(ip) {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

/* ----------------------------------------------------------------- probing */

/**
 * Send one UDP payload per host and collect replies until the deadline.
 * @returns {Promise<Map<string, Buffer>>} responder IP -> raw payload
 */
function udpSweep(payloadFor, port, ips, waitMs) {
  return new Promise((resolve) => {
    const replies = new Map();
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let finished = false;

    const finish = () => {
      if (finished) return;
      finished = true;
      try { socket.close(); } catch { /* already closed */ }
      resolve(replies);
    };

    socket.on('message', (msg, rinfo) => {
      if (!replies.has(rinfo.address)) replies.set(rinfo.address, msg);
    });
    socket.on('error', finish);

    socket.bind(0, () => {
      let i = 0;
      // Stagger sends so a burst of 250 packets does not get dropped wholesale.
      const pump = () => {
        if (finished) return;
        const deadline = Date.now() + 15;
        while (i < ips.length && Date.now() < deadline) {
          const ip = ips[i++];
          const payload = payloadFor(ip);
          try { socket.send(payload, port, ip); } catch { /* unreachable host */ }
        }
        if (i < ips.length) setTimeout(pump, 5);
        else setTimeout(finish, waitMs);
      };
      pump();
    });
  });
}

function sanitize(name) {
  if (!name) return null;
  const clean = name.trim().replace(/\.$/, '');
  if (!clean || clean.length > 253) return null;
  if (!/^[\w.-]+$/.test(clean)) return null;
  return clean;
}

async function mdnsNames(ips, waitMs) {
  const replies = await udpSweep(
    (ip) => buildQuery(reverseZone(ip), 12, 0x8001), // QU bit set: answer unicast
    5353,
    ips,
    waitMs,
  );
  const out = new Map();
  for (const [ip, msg] of replies) {
    const name = sanitize(firstPtrAnswer(msg));
    if (name) out.set(ip, { name, source: 'mDNS' });
  }
  return out;
}

// NetBIOS node-status query for the wildcard name "*".
const NBSTAT_NAME = '*'.padEnd(16, '\0');
function nbstatQuery() {
  const encoded = Buffer.from(
    [...NBSTAT_NAME].flatMap((ch) => {
      const b = ch.charCodeAt(0);
      return [0x41 + (b >> 4), 0x41 + (b & 0x0f)];
    }),
  );
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x4e42, 0); // arbitrary transaction id
  header.writeUInt16BE(0x0000, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(0x0021, 0); // NBSTAT
  tail.writeUInt16BE(0x0001, 2); // IN
  return Buffer.concat([header, Buffer.from([encoded.length]), encoded, Buffer.from([0]), tail]);
}

function parseNbstat(buf) {
  // header(12) + question(1+32+1+4=38) + RR header(38 name + 10) = 98
  const rdataStart = 12 + 38 + 38 + 10;
  if (buf.length <= rdataStart) return null;
  const count = buf[rdataStart];
  let pos = rdataStart + 1;
  for (let i = 0; i < count && pos + 18 <= buf.length; i++, pos += 18) {
    const raw = buf.slice(pos, pos + 15).toString('ascii').trim();
    const suffix = buf[pos + 15];
    const flags = buf.readUInt16BE(pos + 16);
    const isGroup = (flags & 0x8000) !== 0;
    if (suffix === 0x00 && !isGroup && raw && raw !== '__MSBROWSE__') return raw;
  }
  return null;
}

async function netbiosNames(ips, waitMs) {
  const query = nbstatQuery();
  const replies = await udpSweep(() => query, 137, ips, waitMs);
  const out = new Map();
  for (const [ip, msg] of replies) {
    const name = sanitize(parseNbstat(msg));
    if (name) out.set(ip, { name, source: 'NetBIOS' });
  }
  return out;
}

async function reverseDns(ips, concurrency = 24) {
  const out = new Map();
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, ips.length) }, async () => {
    while (cursor < ips.length) {
      const ip = ips[cursor++];
      try {
        const names = await dns.reverse(ip);
        const name = sanitize(names[0]);
        if (name) out.set(ip, { name, source: 'DNS' });
      } catch { /* no PTR record */ }
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Resolve names for a list of IPs, preferring the most descriptive source.
 * @returns {Promise<Map<string, {name: string, source: string}>>}
 */
export async function resolveNames(ips, { waitMs = 1500, onProgress } = {}) {
  if (!ips.length) return new Map();

  const report = (step) => onProgress?.({ task: step });

  report('mDNS query');
  const [mdns, netbios, ptr] = await Promise.all([
    mdnsNames(ips, waitMs),
    netbiosNames(ips, waitMs),
    reverseDns(ips),
  ]);

  const merged = new Map();
  // mDNS names are the most specific (".local" identities the owner chose),
  // then NetBIOS, then whatever DNS happens to know.
  for (const source of [ptr, netbios, mdns]) {
    for (const [ip, entry] of source) merged.set(ip, entry);
  }
  return merged;
}
