import { run, has } from '../lib/exec.js';
import { parseXml, find, kid, kids } from '../lib/xml.js';
import { normalizeMac } from '../lib/oui.js';

/**
 * nmap driver. All invocations write XML to stdout so nothing touches disk, and
 * `--stats-every` lets us surface live progress while a scan runs.
 */

export async function nmapAvailable() {
  return has('nmap');
}

export async function nmapVersion() {
  const res = await run('nmap', ['--version'], { timeout: 8000 });
  const m = res.stdout.match(/Nmap version ([\d.]+)/);
  return m ? m[1] : null;
}

/** nmap needs root for ARP host discovery, SYN scans and OS fingerprinting. */
export function isPrivileged() {
  return typeof process.getuid === 'function' ? process.getuid() === 0 : false;
}

function withSudo(args, useSudo) {
  return useSudo && !isPrivileged()
    ? { cmd: 'sudo', args: ['-n', 'nmap', ...args] }
    : { cmd: 'nmap', args };
}

function streamProgress(onProgress) {
  let buffer = '';
  return (chunk) => {
    if (!onProgress) return;
    buffer += chunk;
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      const m = line.match(/<taskprogress\s+task="([^"]+)"[^>]*percent="([\d.]+)"[^>]*remaining="(\d+)"/);
      if (m) onProgress({ task: m[1], percent: Number(m[2]), remainingSeconds: Number(m[3]) });
    }
  };
}

function parseHost(hostEl) {
  const state = kid(hostEl, 'status')?.attrs.state;
  if (state !== 'up') return null;

  let ip = null;
  let mac = null;
  let vendor = null;
  for (const addr of kids(hostEl, 'address')) {
    if (addr.attrs.addrtype === 'ipv4') ip = addr.attrs.addr;
    if (addr.attrs.addrtype === 'mac') {
      mac = normalizeMac(addr.attrs.addr);
      vendor = addr.attrs.vendor || null;
    }
  }
  if (!ip) return null;

  const hostnames = kids(kid(hostEl, 'hostnames') || { children: [] }, 'hostname')
    .map((h) => h.attrs.name)
    .filter(Boolean);

  const ports = find(hostEl, 'port')
    .filter((p) => kid(p, 'state')?.attrs.state === 'open')
    .map((p) => {
      const svc = kid(p, 'service');
      return {
        port: Number(p.attrs.portid),
        protocol: p.attrs.protocol || 'tcp',
        service: svc?.attrs.name || null,
        product: svc?.attrs.product || null,
        version: svc?.attrs.version || null,
        extra: svc?.attrs.extrainfo || null,
      };
    })
    .sort((a, b) => a.port - b.port);

  const osMatches = find(hostEl, 'osmatch')
    .map((m) => ({ name: m.attrs.name, accuracy: Number(m.attrs.accuracy) }))
    .sort((a, b) => b.accuracy - a.accuracy);

  const times = kid(hostEl, 'times');
  const distance = kid(hostEl, 'distance');
  const uptime = kid(hostEl, 'uptime');

  return {
    ip,
    mac,
    vendor,
    hostnames,
    hostname: hostnames[0] || null,
    ports,
    os: osMatches[0]?.name || null,
    osAccuracy: osMatches[0]?.accuracy ?? null,
    osMatches: osMatches.slice(0, 3),
    // nmap reports smoothed RTT in microseconds.
    rttMs: times?.attrs.srtt ? Number(times.attrs.srtt) / 1000 : null,
    hops: distance?.attrs.value !== undefined ? Number(distance.attrs.value) : null,
    uptimeSeconds: uptime?.attrs.seconds ? Number(uptime.attrs.seconds) : null,
    reason: kid(hostEl, 'status')?.attrs.reason || null,
  };
}

function parseRun(xml) {
  const doc = parseXml(xml);
  const runEl = kid(doc, 'nmaprun');
  const hosts = find(runEl || doc, 'host').map(parseHost).filter(Boolean);
  const finished = find(runEl || doc, 'finished')[0];
  return {
    hosts,
    args: runEl?.attrs.args || null,
    elapsed: finished?.attrs.elapsed ? Number(finished.attrs.elapsed) : null,
    summary: finished?.attrs.summary || null,
  };
}

/**
 * Host discovery (`-sn`). With root privileges on a local subnet nmap uses ARP,
 * which finds devices that ignore ping — the single biggest quality win here.
 */
export async function discover(targets, { sudo = false, resolveNames = true, onProgress, timeout = 300000 } = {}) {
  const args = [
    '-sn',
    '-oX', '-',
    '--stats-every', '2s',
    '-T4',
    '--host-timeout', '30s',
  ];
  if (resolveNames) args.push('--system-dns'); // picks up .local / mDNS names
  else args.push('-n');
  args.push(...targets);

  const { cmd, args: finalArgs } = withSudo(args, sudo);
  const res = await run(cmd, finalArgs, { timeout, onStdout: streamProgress(onProgress) });

  if (!res.stdout.includes('<nmaprun')) {
    return { hosts: [], error: (res.stderr || res.stdout || 'nmap produced no output').trim().slice(0, 400) };
  }
  return parseRun(res.stdout);
}

const PROFILES = {
  quick: { topPorts: 0 },
  normal: { topPorts: 100, hostTimeout: '90s', serviceVersion: false, osDetect: false },
  deep: { topPorts: 500, hostTimeout: '180s', serviceVersion: true, osDetect: true },
};

/** Hosts per nmap invocation — see the note in `probe`. */
const CHUNK_SIZE = 12;

function chunk(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Port / service / OS probe against an explicit host list. `-Pn` because
 * discovery already proved these hosts are up.
 *
 * The host list is scanned in small batches on purpose: `--host-timeout`
 * discards *all* results for a host that runs over, and when dozens of hosts
 * share one invocation they share the bandwidth too, so every one of them
 * trips the timeout and the scan returns nothing. Small batches keep each
 * host's wall-clock inside its budget.
 */
export async function probe(ips, { profile = 'normal', sudo = false, onProgress, timeout = 900000 } = {}) {
  const conf = PROFILES[profile] || PROFILES.normal;
  if (!conf.topPorts || ips.length === 0) return { hosts: [] };

  const privileged = sudo || isPrivileged();
  const batches = chunk(ips, CHUNK_SIZE);
  const hosts = [];
  const errors = [];

  for (const [index, batch] of batches.entries()) {
    const args = [
      '-Pn',
      '-n',
      '--top-ports', String(conf.topPorts),
      '-T4',
      '--open',
      '--host-timeout', conf.hostTimeout,
      '--max-retries', '1',
      '-oX', '-',
      '--stats-every', '2s',
    ];
    if (conf.serviceVersion) args.push('-sV', '--version-intensity', '2');
    if (conf.osDetect && privileged) args.push('-O', '--osscan-limit', '--osscan-guess');
    if (privileged) args.push('-sS');
    args.push(...batch);

    const { cmd, args: finalArgs } = withSudo(args, sudo);
    // Rescale each batch's progress onto the whole probe.
    const scaled = onProgress
      ? (p) => onProgress({
          ...p,
          percent: ((index + (p.percent || 0) / 100) / batches.length) * 100,
          batch: `${index + 1}/${batches.length}`,
        })
      : undefined;

    const res = await run(cmd, finalArgs, {
      timeout: Math.max(60000, Math.round(timeout / batches.length)),
      onStdout: streamProgress(scaled),
    });

    if (res.stdout.includes('<nmaprun')) {
      hosts.push(...parseRun(res.stdout).hosts);
    } else {
      errors.push((res.stderr || 'no output').trim().slice(0, 200));
    }
  }

  return {
    hosts,
    error: errors.length ? `${errors.length}/${batches.length} batches failed: ${errors[0]}` : undefined,
  };
}

/** Can we escalate without an interactive password prompt? */
export async function sudoAvailable() {
  if (isPrivileged()) return true;
  const res = await run('sudo', ['-n', 'true'], { timeout: 5000 });
  return res.ok;
}
