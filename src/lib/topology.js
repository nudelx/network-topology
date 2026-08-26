/**
 * Turns a flat scan model into a topology tree.
 *
 * Deliberately free of Node built-ins: the HTTP server serves this exact file
 * to the browser so the page and the CLI build identical trees from one
 * implementation.
 *
 * Shape of the tree the rest of the app consumes:
 *   { id, kind, label, sublabel, icon, ip, device?, children: [] }
 *   kind: 'self' | 'gateway' | 'subnet' | 'group' | 'device' | 'hop' | 'internet'
 */

import { CATEGORIES } from './classify.js';

const GROUP_ORDER = Object.entries(CATEGORIES)
  .sort((a, b) => a[1].order - b[1].order)
  .map(([key]) => key);

function stripLocal(name) {
  return String(name || '').replace(/\.local$/i, '');
}

function deviceLabel(device) {
  if (device.hostname) return stripLocal(device.hostname);
  if (device.vendor && !/randomized/i.test(device.vendor)) return `${device.vendor} device`;
  return device.ip;
}

function deviceNode(device) {
  const cat = CATEGORIES[device.category] || CATEGORIES.unknown;
  return {
    id: `dev:${device.ip}`,
    kind: 'device',
    label: deviceLabel(device),
    sublabel: device.ip,
    icon: cat.icon,
    category: device.category,
    ip: device.ip,
    device,
    children: [],
  };
}

/**
 * @param {object} model  { meta, subnets, devices, uplink }
 * @param {object} opts   { groupBy: 'category'|'vendor'|'none' }
 */
export function buildTree(model, { groupBy = 'category' } = {}) {
  const devices = model.devices || [];
  const subnets = (model.subnets || []).filter((s) => s.scannable !== false);
  const self = devices.find((d) => d.isSelf);

  const root = {
    id: 'root',
    kind: 'self',
    label: stripLocal(model.meta?.host?.hostname || self?.hostname) || 'this machine',
    sublabel: self?.ip || 'scanner',
    icon: '🖥️',
    device: self || null,
    children: [],
  };

  const claimed = new Set(self ? [self.ip] : []);

  for (const subnet of subnets) {
    const members = devices.filter((d) => d.subnet === subnet.cidr && !claimed.has(d.ip));
    const gatewayDevice = members.find((d) => d.ip === subnet.gateway);

    let branch;
    if (subnet.gateway) {
      branch = gatewayDevice
        ? { ...deviceNode(gatewayDevice), kind: 'gateway', icon: CATEGORIES.router.icon }
        : {
            id: `gw:${subnet.gateway}`,
            kind: 'gateway',
            label: 'Gateway',
            sublabel: subnet.gateway,
            icon: CATEGORIES.router.icon,
            ip: subnet.gateway,
            device: null,
            children: [],
          };
      branch.sublabel = `${subnet.gateway} · ${subnet.cidr}`;
      if (gatewayDevice) claimed.add(gatewayDevice.ip);
    } else {
      branch = {
        id: `net:${subnet.cidr}`,
        kind: 'subnet',
        label: subnet.cidr,
        sublabel: subnet.name,
        icon: '🔗',
        device: null,
        children: [],
      };
    }

    branch.subnet = subnet.cidr;
    const rest = members.filter((d) => !claimed.has(d.ip));
    branch.children = groupDevices(rest, groupBy);
    root.children.push(branch);
  }

  // Devices that fell outside any scanned subnet (e.g. an explicit --target).
  const orphans = devices.filter((d) => !claimed.has(d.ip) && !subnets.some((s) => s.cidr === d.subnet));
  if (orphans.length) {
    root.children.push({
      id: 'net:other',
      kind: 'subnet',
      label: 'Other targets',
      sublabel: `${orphans.length} host${orphans.length === 1 ? '' : 's'}`,
      icon: '🔗',
      device: null,
      children: groupDevices(orphans, groupBy),
    });
  }

  attachUplink(root, model);
  return root;
}

function groupDevices(devices, groupBy) {
  if (groupBy === 'none' || devices.length === 0) {
    return sortDevices(devices).map(deviceNode);
  }

  const buckets = new Map();
  for (const d of devices) {
    const key = groupBy === 'vendor'
      ? (d.vendor || 'Unknown vendor')
      : d.category;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(d);
  }

  const keys = [...buckets.keys()].sort((a, b) => {
    if (groupBy === 'category') return GROUP_ORDER.indexOf(a) - GROUP_ORDER.indexOf(b);
    return String(a).localeCompare(String(b));
  });

  return keys.map((key) => {
    const members = sortDevices(buckets.get(key));
    const meta = groupBy === 'category' ? (CATEGORIES[key] || CATEGORIES.unknown) : null;
    return {
      id: `grp:${groupBy}:${key}`,
      kind: 'group',
      label: meta ? meta.label : String(key),
      sublabel: `${members.length} device${members.length === 1 ? '' : 's'}`,
      icon: meta ? meta.icon : '🏷️',
      category: groupBy === 'category' ? key : undefined,
      device: null,
      children: members.map(deviceNode),
    };
  });
}

function sortDevices(devices) {
  return [...devices].sort((a, b) => ipKey(a.ip) - ipKey(b.ip));
}

function ipKey(ip) {
  return String(ip).split('.').reduce((n, p) => n * 256 + Number(p), 0);
}

/**
 * Hangs the traceroute path off the gateway it starts from, so the map shows
 * where the LAN ends and the ISP begins.
 */
function attachUplink(root, model) {
  const uplink = model.uplink;
  if (!uplink || !uplink.hops || uplink.hops.length === 0) return;

  const firstHop = uplink.hops[0]?.ip;
  const anchor = root.children.find((c) => c.kind === 'gateway' && c.ip === firstHop)
    || root.children.find((c) => c.kind === 'gateway')
    || root;

  let cursor = {
    id: 'uplink',
    kind: 'hop',
    label: 'Uplink',
    sublabel: `traceroute to ${uplink.target}`,
    icon: '⬆️',
    device: null,
    children: [],
  };
  anchor.children.unshift(cursor);

  const beyond = uplink.hops.filter((h) => h.ttl > 1);
  for (const hop of beyond) {
    const node = {
      id: `hop:${hop.ttl}:${hop.ip || 'anon'}`,
      kind: 'hop',
      label: hop.ip || '* * * (no reply)',
      sublabel: `hop ${hop.ttl}${hop.rtt != null ? ` · ${hop.rtt} ms` : ''}`,
      icon: hop.ip ? '🔀' : '·',
      ip: hop.ip,
      device: null,
      hop,
      children: [],
    };
    cursor.children.push(node);
    cursor = node;
  }

  cursor.children.push({
    id: 'internet',
    kind: 'internet',
    label: 'Internet',
    sublabel: uplink.reached ? `reached ${uplink.target}` : `toward ${uplink.target}`,
    icon: '☁️',
    device: null,
    children: [],
  });
}

/**
 * How many real devices a subtree represents — including the node itself when
 * it *is* a device (the gateway and this machine both are), so the root badge
 * agrees with the device count in the summary.
 */
export function countDevices(node) {
  const own = node.kind === 'device' || node.kind === 'gateway' || (node.kind === 'self' && node.device) ? 1 : 0;
  return own + (node.children || []).reduce((sum, c) => sum + countDevices(c), 0);
}

/** ASCII rendering for the terminal. */
export function treeToText(node, prefix = '', isLast = true, isRoot = true) {
  const lines = [];
  const connector = isRoot ? '' : (isLast ? '└─ ' : '├─ ');
  const label = `${node.icon ? `${node.icon} ` : ''}${node.label}${node.sublabel ? `  (${node.sublabel})` : ''}`;
  lines.push(`${prefix}${connector}${label}`);

  const childPrefix = isRoot ? '' : prefix + (isLast ? '   ' : '│  ');
  const children = node.children || [];
  children.forEach((child, i) => {
    lines.push(...treeToText(child, childPrefix, i === children.length - 1, false));
  });
  return lines;
}
