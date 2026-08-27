import { run, has } from '../lib/exec.js';

/**
 * Active-connection sampling: what this machine currently has open.
 *
 * Two jobs. It is the fallback traffic source when packet capture is not
 * available — no privileges required, but it can only see conversations this
 * host is one end of, and it reports no byte counts. It also runs alongside a
 * capture, where it is the only thing that can say *which process* a flow
 * belongs to, since a packet on the wire carries no such label.
 */

const LOOPBACK = /^(127\.|::1$|0\.0\.0\.0$)/;
const WILDCARD = /^(\*|::|0\.0\.0\.0|\[?::\]?)$/;

/**
 * @returns {Promise<{ok: boolean, method: string, connections: object[], warning: string|null}>}
 *   connections: {protocol, localIp, localPort, remoteIp, remotePort, state, process, pid}
 */
export async function pollConnections({ sudo = false, includeLoopback = false } = {}) {
  const attempts = process.platform === 'linux'
    ? [viaSs, viaLsof, viaNetstat]
    : [viaLsof, viaNetstat];

  for (const attempt of attempts) {
    const result = await attempt({ sudo });
    if (result) {
      const connections = result.connections.filter((c) => {
        if (!c.remoteIp || !c.localIp) return false;
        if (WILDCARD.test(c.remoteIp) || WILDCARD.test(c.localIp)) return false;
        if (!includeLoopback && (LOOPBACK.test(c.remoteIp) || LOOPBACK.test(c.localIp))) return false;
        return c.remoteIp !== c.localIp || c.remotePort !== c.localPort;
      });
      return { ok: true, method: result.method, connections, warning: result.warning || null };
    }
  }

  return {
    ok: false,
    method: 'none',
    connections: [],
    warning: 'No way to list connections on this platform (tried lsof, ss, netstat).',
  };
}

/* --------------------------------------------------------------------- lsof */

async function viaLsof({ sudo }) {
  if (!(await has('lsof'))) return null;
  // -F emits one tagged field per line, which is far less fragile than the
  // column layout, whose widths shift with long process names.
  const args = ['-nP', '-i', '-F', 'pcnPT'];

  let res = null;
  let elevated = false;
  if (sudo) {
    res = await run('sudo', ['-n', 'lsof', ...args], { timeout: 12000 });
    elevated = Boolean(res.stdout.trim());
  }
  // `sudo -n lsof` fails outright with no cached credentials. Retrying
  // unprivileged keeps process attribution, which netstat cannot provide at
  // all — the previous behaviour dropped straight to netstat and lost it.
  if (!res || !res.stdout.trim()) res = await run('lsof', args, { timeout: 12000 });

  // lsof exits 1 when some sockets could not be read, which is normal
  // unprivileged. Only a total lack of output means failure.
  if (!res.stdout.trim()) return null;

  const connections = [];
  let command = null;
  let pid = null;
  let protocol = null;
  let pending = null;

  // lsof emits the socket name (`n`) before its TCP state (`TST=`), so a record
  // is held open until the next descriptor begins.
  const flush = () => {
    if (pending) connections.push(pending);
    pending = null;
  };

  for (const line of res.stdout.split('\n')) {
    const tag = line[0];
    const value = line.slice(1);
    switch (tag) {
      case 'p':
        flush();
        pid = Number(value) || null;
        break;
      case 'c':
        command = value || null;
        break;
      case 'f':
        flush();
        protocol = null;
        break;
      case 'P':
        protocol = value.toLowerCase();
        break;
      case 'T': {
        const st = value.match(/^ST=(.*)$/);
        if (st && pending) pending.state = st[1];
        break;
      }
      case 'n': {
        const parsed = parseLsofName(value);
        if (parsed) {
          pending = { ...parsed, protocol: protocol || parsed.protocol, state: null, process: command, pid };
        }
        break;
      }
      default:
        break;
    }
  }
  flush();

  return {
    method: 'lsof',
    connections,
    warning: elevated
      ? null
      : 'lsof ran unprivileged, so only this user\'s processes are attributed.',
  };
}

/** `192.168.1.5:51000->142.250.1.1:443` or `[::1]:5353` (a listener, skipped). */
function parseLsofName(name) {
  const arrow = name.indexOf('->');
  if (arrow === -1) return null;
  const local = splitHostPort(name.slice(0, arrow));
  const remote = splitHostPort(name.slice(arrow + 2));
  if (!local || !remote) return null;
  return {
    localIp: local.host,
    localPort: local.port,
    remoteIp: remote.host,
    remotePort: remote.port,
    protocol: null,
  };
}

/* ----------------------------------------------------------------------- ss */

async function viaSs({ sudo }) {
  if (!(await has('ss'))) return null;
  const args = ['-tunapH'];
  const res = sudo
    ? await run('sudo', ['-n', 'ss', ...args], { timeout: 12000 })
    : await run('ss', args, { timeout: 12000 });
  if (!res.stdout.trim()) return null;

  const connections = [];
  for (const line of res.stdout.split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5) continue;
    const [protocol, state, , , localRaw, remoteRaw] = cols;
    if (!/^(tcp|udp)$/i.test(protocol)) continue;
    const local = splitHostPort(localRaw);
    const remote = splitHostPort(remoteRaw);
    if (!local || !remote) continue;
    const users = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    connections.push({
      protocol: protocol.toLowerCase(),
      localIp: local.host,
      localPort: local.port,
      remoteIp: remote.host,
      remotePort: remote.port,
      state,
      process: users ? users[1] : null,
      pid: users ? Number(users[2]) : null,
    });
  }
  return { method: 'ss', connections, warning: null };
}

/* ------------------------------------------------------------------ netstat */

async function viaNetstat({ sudo }) {
  if (!(await has('netstat'))) return null;
  const args = process.platform === 'linux' ? ['-tun', '-a'] : ['-an'];
  const res = await run('netstat', args, { timeout: 12000 });
  if (!res.stdout.trim()) return null;

  const connections = [];
  for (const line of res.stdout.split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5) continue;
    if (!/^(tcp|udp)/i.test(cols[0])) continue;
    // BSD: proto recvq sendq local foreign [state].  Linux: proto recvq sendq local foreign state
    const local = splitHostPort(cols[3]);
    const remote = splitHostPort(cols[4]);
    if (!local || !remote) continue;
    connections.push({
      protocol: cols[0].toLowerCase().startsWith('udp') ? 'udp' : 'tcp',
      localIp: local.host,
      localPort: local.port,
      remoteIp: remote.host,
      remotePort: remote.port,
      state: cols[5] || null,
      process: null,
      pid: null,
    });
  }
  return {
    method: 'netstat',
    connections,
    warning: 'netstat reports no process names, so flows are not attributed.',
  };
}

/* ------------------------------------------------------------------- shared */

/**
 * Accepts every shape these tools emit: `host:port` (lsof, ss),
 * `[v6]:port` (ss), and `a.b.c.d.port` / `v6.port` (BSD netstat).
 */
export function splitHostPort(token) {
  const raw = String(token || '').trim();
  if (!raw || raw === '*') return null;

  const bracketed = raw.match(/^\[(.+)\]:(\d+|\*)$/);
  if (bracketed) return finish(bracketed[1], bracketed[2]);

  const colon = raw.lastIndexOf(':');
  const dot = raw.lastIndexOf('.');
  const sep = Math.max(colon, dot);
  if (sep <= 0 || sep === raw.length - 1) return null;

  // An unbracketed IPv6 address has several colons; the port is after the last
  // separator either way, so only the host needs care.
  const host = raw.slice(0, sep).replace(/^\[|\]$/g, '');
  return finish(host, raw.slice(sep + 1));
}

function finish(host, portRaw) {
  if (!host || host === '*') return null;
  const port = portRaw === '*' ? null : Number(portRaw);
  if (port !== null && (!Number.isInteger(port) || port < 0 || port > 65535)) return null;
  // BSD netstat truncates a v6 scope as `fe80::1%en0`.
  return { host: host.split('%')[0], port };
}

/** `tcp:192.168.1.5:51000` -> process name, for enriching captured packets. */
export function processIndex(connections) {
  const index = new Map();
  for (const c of connections) {
    if (!c.process) continue;
    index.set(`${c.protocol}:${c.localIp}:${c.localPort}`, c.process);
    index.set(`${c.protocol}:${c.remoteIp}:${c.remotePort}`, c.process);
  }
  return index;
}
