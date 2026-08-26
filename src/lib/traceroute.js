import { run, has } from './exec.js';

/**
 * Trace the path toward an off-net address so the map can show the uplink
 * above the local gateway. Hops that time out are kept as anonymous
 * placeholders — dropping them would misrepresent the distance.
 *
 * @returns {Promise<{target: string, hops: Array<{ttl: number, ip: string|null, rtt: number|null}>}>}
 */
export async function traceroute(target = '1.1.1.1', { maxHops = 12, timeout = 45000 } = {}) {
  const win = process.platform === 'win32';
  const cmd = win ? 'tracert' : 'traceroute';

  if (!await has(cmd)) return { target, hops: [], unavailable: true };

  const args = win
    ? ['-d', '-h', String(maxHops), '-w', '900', target]
    : ['-n', '-q', '1', '-w', '1', '-m', String(maxHops), target];

  const res = await run(cmd, args, { timeout });
  const hops = [];

  for (const line of res.stdout.split('\n')) {
    const m = line.match(/^\s*(\d{1,2})\s+(.*)$/);
    if (!m) continue;
    const ttl = Number(m[1]);
    if (!Number.isFinite(ttl) || ttl < 1 || ttl > maxHops) continue;
    const rest = m[2];
    const ipMatch = rest.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const rttMatch = rest.match(/([\d.]+)\s*ms/);
    hops.push({
      ttl,
      ip: ipMatch ? ipMatch[1] : null,
      rtt: rttMatch ? Number(rttMatch[1]) : null,
      timedOut: !ipMatch,
    });
  }

  // Collapse duplicate TTL lines (some traceroutes print one line per probe).
  const byTtl = new Map();
  for (const hop of hops) {
    const existing = byTtl.get(hop.ttl);
    if (!existing || (existing.timedOut && !hop.timedOut)) byTtl.set(hop.ttl, hop);
  }

  return {
    target,
    hops: [...byTtl.values()].sort((a, b) => a.ttl - b.ttl),
    reached: hops.some((h) => h.ip === target),
  };
}
