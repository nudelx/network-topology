import net from 'node:net';
import { run } from '../lib/exec.js';
import { hostsIn } from '../lib/net.js';
import { arpTable } from '../lib/arp.js';

/**
 * Dependency-free fallback discovery for machines without nmap: an ICMP sweep,
 * a TCP connect probe for the (common) hosts that drop ping, and the ARP cache
 * to catch anything that answered neither but did talk to us.
 */

const DEFAULT_PORTS = [22, 80, 443, 445, 139, 548, 631, 8080, 8443, 9100, 5000, 53, 3389, 5900, 1400, 8009, 32400];

const PING_ARGS = {
  darwin: (ip) => ['-c', '1', '-W', '900', '-n', ip],
  linux: (ip) => ['-c', '1', '-W', '1', '-n', ip],
  win32: (ip) => ['-n', '1', '-w', '900', ip],
};

async function pingOnce(ip) {
  const argsFor = PING_ARGS[process.platform] || PING_ARGS.linux;
  const cmd = process.platform === 'win32' ? 'ping' : 'ping';
  const res = await run(cmd, argsFor(ip), { timeout: 3000 });
  if (!res.ok) return null;
  if (/unreachable|100(\.0)?% packet loss|100% loss/i.test(res.stdout)) return null;
  const m = res.stdout.match(/time[=<]\s*([\d.]+)\s*ms/i);
  return { rttMs: m ? Number(m[1]) : null };
}

function tcpProbe(ip, port, timeout = 700) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, ip);
  });
}

/** Run `tasks` with a bounded number in flight. */
async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return results;
}

async function reverseLookup(ip) {
  const { promises: dns } = await import('node:dns');
  try {
    const names = await dns.reverse(ip);
    return names[0] || null;
  } catch {
    return null;
  }
}

/**
 * @param {string[]} cidrs
 * @returns {Promise<{hosts: Array<object>}>} hosts shaped like nmap.js output
 */
export async function sweep(cidrs, {
  concurrency = 96,
  ports = DEFAULT_PORTS,
  probePorts = true,
  resolveNames = true,
  onProgress,
} = {}) {
  const targets = [...new Set(cidrs.flatMap((c) => hostsIn(c)))];
  const alive = new Map();
  let done = 0;

  const report = (phase) => {
    if (onProgress) {
      onProgress({
        task: phase,
        percent: targets.length ? Math.round((done / targets.length) * 100) : 100,
        found: alive.size,
      });
    }
  };

  // Phase 1: ICMP.
  await pool(targets, concurrency, async (ip) => {
    const res = await pingOnce(ip);
    if (res) alive.set(ip, { ip, rttMs: res.rttMs, ports: [], reason: 'echo-reply' });
    done++;
    if (done % 16 === 0) report('ICMP sweep');
  });
  done = targets.length;
  report('ICMP sweep');

  // Phase 2: TCP connect on the hosts that stayed silent, plus port data for all.
  if (probePorts) {
    done = 0;
    const jobs = [];
    for (const ip of targets) {
      for (const port of ports) jobs.push([ip, port]);
    }
    await pool(jobs, Math.max(concurrency, 256), async ([ip, port]) => {
      const open = await tcpProbe(ip, port);
      if (open) {
        const host = alive.get(ip) || { ip, rttMs: null, ports: [], reason: 'syn-ack' };
        host.ports.push({ port, protocol: 'tcp', service: null, product: null, version: null });
        alive.set(ip, host);
      }
      done++;
      if (done % 256 === 0 && onProgress) {
        onProgress({ task: 'TCP probe', percent: Math.round((done / jobs.length) * 100), found: alive.size });
      }
    });
    if (onProgress) onProgress({ task: 'TCP probe', percent: 100, found: alive.size });
  }

  // Phase 3: ARP cache — the sweep itself populated it, so this is nearly free.
  const arp = await arpTable();
  for (const [ip, entry] of arp) {
    if (!ipInCidrs(ip, cidrs)) continue;
    const host = alive.get(ip) || { ip, rttMs: null, ports: [], reason: 'arp-cache' };
    host.mac = entry.mac;
    alive.set(ip, host);
  }

  const hosts = [...alive.values()];
  for (const h of hosts) h.ports.sort((a, b) => a.port - b.port);

  if (resolveNames) {
    await pool(hosts, 32, async (host) => {
      host.hostname = await reverseLookup(host.ip);
      host.hostnames = host.hostname ? [host.hostname] : [];
    });
  }

  return { hosts, scanned: targets.length };
}

function ipInCidrs(ip, cidrs) {
  // Lazy import avoided: parseCidr is cheap enough to re-derive per call.
  return cidrs.some((c) => {
    const [base, prefixStr] = c.split('/');
    const prefix = Number(prefixStr ?? 32);
    const toInt = (s) => s.split('.').reduce((n, p) => n * 256 + Number(p), 0);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (toInt(base) & mask) === (toInt(ip) & mask);
  });
}
