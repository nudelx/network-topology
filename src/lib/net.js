import os from 'node:os';
import { run } from './exec.js';

/* ---------------------------------------------------------------- IPv4 math */

export function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n;
}

export function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function maskToPrefix(mask) {
  const n = ipToInt(mask);
  if (n === null) return null;
  let prefix = 0;
  let seenZero = false;
  for (let bit = 31; bit >= 0; bit--) {
    if ((n >>> bit) & 1) {
      if (seenZero) return null; // non-contiguous mask
      prefix++;
    } else {
      seenZero = true;
    }
  }
  return prefix;
}

export function prefixToMask(prefix) {
  return intToIp(prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);
}

/** Parse "10.0.0.0/24" (or a bare address, treated as /32) into range info. */
export function parseCidr(cidr) {
  const [addr, prefixStr] = String(cidr).trim().split('/');
  const base = ipToInt(addr);
  if (base === null) return null;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & maskInt) >>> 0;
  const broadcast = (network | (~maskInt >>> 0)) >>> 0;
  return {
    cidr: `${intToIp(network)}/${prefix}`,
    prefix,
    network,
    broadcast,
    size: broadcast - network + 1,
    contains: (ip) => {
      const n = ipToInt(ip);
      return n !== null && n >= network && n <= broadcast;
    },
  };
}

/** Usable host addresses in a CIDR (excludes network/broadcast for /31 and wider). */
export function hostsIn(cidr) {
  const r = parseCidr(cidr);
  if (!r) return [];
  const out = [];
  const start = r.prefix >= 31 ? r.network : r.network + 1;
  const end = r.prefix >= 31 ? r.broadcast : r.broadcast - 1;
  for (let n = start; n <= end; n++) out.push(intToIp(n));
  return out;
}

/* ------------------------------------------------------------- Local facts */

/** Active non-loopback IPv4 interfaces with their CIDR. */
export function localInterfaces() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      if (a.address.startsWith('169.254.')) continue; // link-local, nothing to scan
      const prefix = a.cidr ? Number(a.cidr.split('/')[1]) : maskToPrefix(a.netmask);
      if (prefix === null || !Number.isFinite(prefix)) continue;
      const range = parseCidr(`${a.address}/${prefix}`);
      out.push({
        name,
        address: a.address,
        netmask: a.netmask,
        mac: a.mac && a.mac !== '00:00:00:00:00:00' ? a.mac : null,
        prefix,
        cidr: range.cidr,
        size: range.size,
      });
    }
  }
  return out;
}

/** Default gateways, keyed by interface where the platform reports one. */
export async function defaultGateways() {
  const platform = process.platform;
  const found = [];

  if (platform === 'darwin' || platform.includes('bsd')) {
    const res = await run('netstat', ['-rn', '-f', 'inet'], { timeout: 8000 });
    for (const line of res.stdout.split('\n')) {
      const m = line.match(/^default\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\S+)/);
      if (m) found.push({ gateway: m[1], iface: m[2] });
    }
  } else if (platform === 'linux') {
    let res = await run('ip', ['-4', 'route', 'show', 'default'], { timeout: 8000 });
    if (!res.ok || !res.stdout.trim()) {
      res = await run('route', ['-n'], { timeout: 8000 });
      for (const line of res.stdout.split('\n')) {
        const m = line.match(/^0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)/);
        if (m) found.push({ gateway: m[1], iface: m[2] });
      }
    } else {
      for (const line of res.stdout.split('\n')) {
        const m = line.match(/default\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:.*\bdev\s+(\S+))?/);
        if (m) found.push({ gateway: m[1], iface: m[2] || null });
      }
    }
  } else if (platform === 'win32') {
    const res = await run('cmd', ['/c', 'route print -4'], { timeout: 8000 });
    for (const line of res.stdout.split('\n')) {
      const m = line.match(/^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/);
      if (m) found.push({ gateway: m[1], iface: null });
    }
  }

  // Dedupe, keeping the first sighting of each gateway address.
  const seen = new Set();
  return found.filter((g) => {
    if (!g.gateway || seen.has(g.gateway)) return false;
    seen.add(g.gateway);
    return true;
  });
}

/**
 * Which local interfaces are worth scanning, each paired with its gateway.
 * VPN/tunnel interfaces and oversized ranges are reported but flagged.
 */
export async function surveyNetwork({ maxHosts = 4096 } = {}) {
  const ifaces = localInterfaces();
  const gateways = await defaultGateways();

  const subnets = ifaces.map((iface) => {
    const gw = gateways.find((g) => g.iface === iface.name)
      || gateways.find((g) => parseCidr(iface.cidr)?.contains(g.gateway));
    const tunnel = /^(utun|tun|tap|ppp|ipsec|wg|zt)/.test(iface.name);
    return {
      ...iface,
      gateway: gw?.gateway ?? null,
      isTunnel: tunnel,
      tooLarge: iface.size > maxHosts,
      scannable: !tunnel && iface.size <= maxHosts && iface.prefix >= 8,
    };
  });

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    subnets,
    gateways,
  };
}
