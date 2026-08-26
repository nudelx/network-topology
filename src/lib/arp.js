import { run, has } from './exec.js';
import { normalizeMac } from './oui.js';

const IP_RE = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
const MAC_RE = /\b([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b/;

/**
 * Read the kernel's ARP/neighbour cache. This is the cheapest source of MAC
 * addresses on the LAN and works without privileges, so it is used both as a
 * fallback discovery method and to enrich nmap results.
 *
 * @returns {Promise<Map<string, {ip: string, mac: string, iface: string|null}>>}
 */
export async function arpTable() {
  const out = new Map();
  const lines = [];

  if (process.platform === 'linux' && await has('ip')) {
    const res = await run('ip', ['-4', 'neigh', 'show'], { timeout: 8000 });
    lines.push(...res.stdout.split('\n'));
  }
  if (lines.length === 0) {
    const args = process.platform === 'win32' ? ['-a'] : ['-an'];
    const res = await run('arp', args, { timeout: 8000 });
    lines.push(...res.stdout.split('\n'));
  }

  for (const line of lines) {
    if (/incomplete|failed|no entry/i.test(line)) continue;
    const ipMatch = line.match(IP_RE);
    const macMatch = line.match(MAC_RE);
    if (!ipMatch || !macMatch) continue;

    const ip = ipMatch[1];
    const mac = normalizeMac(macMatch[1]);
    if (!mac || mac === 'FF:FF:FF:FF:FF:FF' || mac === '00:00:00:00:00:00') continue;
    if (ip.endsWith('.255') || ip.startsWith('224.') || ip.startsWith('239.')) continue;

    const ifaceMatch = line.match(/\b(?:on|dev)\s+([a-zA-Z0-9._-]+)/);
    out.set(ip, { ip, mac, iface: ifaceMatch ? ifaceMatch[1] : null });
  }

  return out;
}
