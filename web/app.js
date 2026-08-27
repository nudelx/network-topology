import { buildTree, countDevices } from '/shared/topology.js';
import { CATEGORIES } from '/shared/classify.js';
import { createCanvas, exportSvgFile, download } from '/canvas.js';
import { createTrafficStore } from '/traffic-store.js';
import { createCaptureControls } from '/capture-controls.js';
import { createTrafficView } from '/traffic.js';
import { createHeatmapView } from '/heatmap.js';

/**
 * Topology map front-end. Imports the same tree builder the CLI uses, lays the
 * tree out left-to-right, and renders it as SVG with pan/zoom, collapsing,
 * search and a device detail drawer.
 *
 * Everything rendered from scan data goes through textContent — hostnames and
 * service banners are attacker-controllable strings.
 */

/* -------------------------------------------------------------------- state */

const state = {
  model: null,
  tree: null,
  nodes: [],
  links: [],
  collapsed: new Set(),
  groupBy: 'category',
  query: '',
  catFilter: new Set(),
  selectedId: null,
  scanning: false,
};

const NODE_W = 208;
const NODE_H = 34;
const ROW_GAP = 10;
const LEVEL_GAP = 76;
const SVG_NS = 'http://www.w3.org/2000/svg';

const $ = (id) => document.getElementById(id);
const dom = {};
for (const id of [
  'map', 'viewport', 'links', 'nodes', 'canvas', 'empty', 'search', 'group',
  'expand', 'collapse', 'fit', 'zoom-in', 'zoom-out', 'export-svg', 'export-json',
  'scan', 'empty-scan', 'profile', 'target', 'sudo', 'progress', 'bar-fill',
  'progress-text', 'stats', 'legend', 'warnings', 'warnings-block', 'meta-line',
  'brand-sub', 'drawer', 'drawer-body', 'drawer-close', 'clear-filter',
]) dom[id] = $(id);

/* ------------------------------------------------------------------ helpers */

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined) node.setAttribute(k, String(v));
  }
  return node;
}

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.className) node.className = opts.className;
  if (opts.text !== undefined) node.textContent = String(opts.text);
  for (const [k, v] of Object.entries(opts.attrs || {})) node.setAttribute(k, String(v));
  for (const child of children) if (child) node.append(child);
  return node;
}

function truncate(str, max) {
  const s = String(str ?? '');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function catColor(node) {
  if (node.kind === 'self') return 'var(--cat-self)';
  if (node.kind === 'hop' || node.kind === 'internet') return 'var(--cat-hop)';
  const key = node.category || (node.kind === 'gateway' ? 'router' : 'unknown');
  return CATEGORIES[key] ? `var(--cat-${key})` : 'var(--cat-unknown)';
}

/* ------------------------------------------------------------- tree pipeline */

/** Text blob a node is searched against. */
function haystack(node) {
  const d = node.device;
  const parts = [node.label, node.sublabel, node.ip];
  if (d) {
    parts.push(d.ip, d.mac, d.vendor, d.hostname, d.os, d.category, ...(d.hostnames || []));
    for (const p of d.ports || []) parts.push(String(p.port), p.label, p.service, p.product);
  }
  return parts.filter(Boolean).join(' ').toLowerCase();
}

/** Prune to nodes matching the active filters, keeping ancestors of matches. */
function filterTree(node) {
  const q = state.query.trim().toLowerCase();
  const cats = state.catFilter;

  const walk = (n) => {
    const children = (n.children || []).map(walk).filter(Boolean);

    let self = true;
    if (n.kind === 'device') {
      if (cats.size && !cats.has(n.category)) self = false;
      if (self && q && !haystack(n).includes(q)) self = false;
    }

    const matched = q ? haystack(n).includes(q) : false;
    if (n.kind !== 'device' && children.length === 0 && (cats.size || q)) {
      // A container that lost every child is noise unless it matched itself.
      if (!matched) return null;
    }
    if (!self && children.length === 0) return null;

    return { ...n, children, _match: matched && Boolean(q) };
  };

  return walk(node) || { ...node, children: [], _match: false };
}

/** Tidy left-to-right layout: depth sets x, leaf order sets y. */
function layout(root) {
  const nodes = [];
  const links = [];
  let cursorY = 0;

  const visit = (node, depth, parent) => {
    const isCollapsed = state.collapsed.has(node.id) && (node.children || []).length > 0;
    const children = isCollapsed ? [] : (node.children || []);

    const placed = {
      ...node,
      depth,
      x: depth * (NODE_W + LEVEL_GAP),
      y: 0,
      collapsed: isCollapsed,
      childCount: (node.children || []).length,
      deviceCount: countDevices(node),
    };
    nodes.push(placed);

    if (children.length === 0) {
      placed.y = cursorY;
      cursorY += NODE_H + ROW_GAP;
    } else {
      const kids = children.map((c) => visit(c, depth + 1, placed));
      placed.y = (kids[0].y + kids[kids.length - 1].y) / 2;
      for (const k of kids) links.push({ source: placed, target: k });
    }

    if (parent) placed.parentId = parent.id;
    return placed;
  };

  visit(root, 0, null);
  return { nodes, links };
}

function rebuild({ keepView = true } = {}) {
  if (!state.model) return;
  state.tree = buildTree(state.model, { groupBy: state.groupBy });
  const filtered = filterTree(state.tree);
  const { nodes, links } = layout(filtered);
  state.nodes = nodes;
  state.links = links;
  render();
  if (!keepView) fitToView();
}

/* ------------------------------------------------------------------ renderer */

function render() {
  dom.links.replaceChildren();
  dom.nodes.replaceChildren();

  const hasQuery = state.query.trim().length > 0;
  const matchIds = new Set(state.nodes.filter((n) => n._match).map((n) => n.id));
  const selectedPath = new Set();
  if (state.selectedId) {
    let cur = state.nodes.find((n) => n.id === state.selectedId);
    while (cur) {
      selectedPath.add(cur.id);
      cur = state.nodes.find((n) => n.id === cur.parentId);
    }
  }

  for (const link of state.links) {
    const x1 = link.source.x + NODE_W;
    const y1 = link.source.y + NODE_H / 2;
    const x2 = link.target.x;
    const y2 = link.target.y + NODE_H / 2;
    const mid = x1 + (x2 - x1) / 2;
    const path = svg('path', {
      class: `link${selectedPath.has(link.target.id) ? ' hot' : ''}`,
      d: `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`,
    });
    dom.links.append(path);
  }

  for (const node of state.nodes) {
    const g = svg('g', {
      class: [
        'node',
        node.kind === 'self' ? 'root' : node.kind,
        node.id === state.selectedId ? 'selected' : '',
        node._match ? 'match' : '',
        hasQuery && matchIds.size && !node._match && !node.children.length ? 'dim' : '',
      ].filter(Boolean).join(' '),
      transform: `translate(${node.x},${node.y})`,
    });

    g.append(svg('rect', { class: 'box', width: NODE_W, height: NODE_H }));
    g.append(svg('rect', { class: 'accent', x: 0, y: 6, width: 3, height: NODE_H - 12, fill: catColor(node) }));

    const icon = svg('text', { class: 'icon', x: 12, y: NODE_H / 2 + 5 });
    icon.textContent = node.icon || '•';
    g.append(icon);

    const label = svg('text', { class: 'label', x: 33, y: node.sublabel ? 15 : 22 });
    label.textContent = truncate(node.label, node.sublabel ? 22 : 26);
    g.append(label);

    if (node.sublabel) {
      const sub = svg('text', { class: 'sub', x: 33, y: 27 });
      sub.textContent = truncate(node.sublabel, 26);
      g.append(sub);
    }

    if (node.childCount > 0) {
      const count = node.kind === 'device' ? node.childCount : node.deviceCount || node.childCount;
      const width = 14 + String(count).length * 7;
      const badge = svg('rect', {
        class: 'badge', x: NODE_W - width - 7, y: NODE_H / 2 - 8,
        width, height: 16, rx: 8,
      });
      const text = svg('text', {
        class: 'badge-text', x: NODE_W - width / 2 - 7, y: NODE_H / 2 + 4,
        'text-anchor': 'middle',
      });
      text.textContent = node.collapsed ? `+${count}` : String(count);
      g.append(badge, text);
    }

    g.addEventListener('click', (event) => {
      event.stopPropagation();
      onNodeClick(node);
    });
    dom.nodes.append(g);
  }

  applyTransform();
}

function contentBounds() {
  if (!state.nodes.length) return { minX: 0, minY: 0, maxX: 1, maxY: 1 };
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of state.nodes) {
    minX = Math.min(minX, n.x);
    minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x + NODE_W);
    maxY = Math.max(maxY, n.y + NODE_H);
  }
  return { minX, minY, maxX, maxY };
}

const canvas = createCanvas({
  svg: dom.map,
  viewport: dom.viewport,
  container: dom.canvas,
  getBounds: contentBounds,
  onBackgroundClick: () => {
    state.selectedId = null;
    closeDrawer();
    render();
  },
});
const { view, applyTransform, fitToView, zoomBy } = canvas;

/* ----------------------------------------------------------- interaction */

function onNodeClick(node) {
  // Pin the clicked node to its current screen position: collapsing a branch
  // changes every sibling's row, and without this the map jumps away.
  const before = state.nodes.find((n) => n.id === node.id);
  const anchor = before
    ? { x: view.x + before.x * view.k, y: view.y + before.y * view.k }
    : null;

  if (node.childCount > 0) {
    if (state.collapsed.has(node.id)) state.collapsed.delete(node.id);
    else state.collapsed.add(node.id);
  }
  state.selectedId = node.id;
  rebuild(); // lay out first, so the drawer can reveal the node's final position

  const after = state.nodes.find((n) => n.id === node.id);
  if (anchor && after) {
    view.x = anchor.x - after.x * view.k;
    view.y = anchor.y - after.y * view.k;
    applyTransform();
  }

  if (node.device || node.hop || node.kind === 'group' || node.kind === 'subnet') openDrawer(node);
}

function eachNode(node, fn) {
  fn(node);
  for (const child of node.children || []) eachNode(child, fn);
}

function setAllCollapsed(collapsed) {
  state.collapsed.clear();
  if (collapsed && state.tree) {
    eachNode(state.tree, (n) => {
      if ((n.children || []).length && n.kind !== 'self') state.collapsed.add(n.id);
    });
  }
  rebuild();
}

/**
 * Collapse the noisy parts on first load so the initial fit is readable: the
 * traceroute chain (deep, and supplementary) and any crowded device group.
 */
function autoCollapse() {
  state.collapsed.clear();
  if (!state.tree) return;
  eachNode(state.tree, (n) => {
    if (n.id === 'uplink' && (n.children || []).length) state.collapsed.add(n.id);
  });
  if (countDevices(state.tree) <= 24) return;
  eachNode(state.tree, (n) => {
    if (n.kind === 'group' && (n.children || []).length >= 6) state.collapsed.add(n.id);
  });
}

/* ------------------------------------------------------------------- drawer */

function openDrawer(node) {
  const body = dom['drawer-body'];
  body.replaceChildren();
  body.append(node.device ? deviceView(node) : containerView(node));
  dom.drawer.hidden = false;
  revealBehindDrawer(node);
}

/** Slide the view left if the drawer would cover the node we just selected. */
function revealBehindDrawer(node) {
  const placed = state.nodes.find((n) => n.id === node.id) || node;
  const drawerWidth = dom.drawer.getBoundingClientRect().width;
  const canvasWidth = dom.canvas.getBoundingClientRect().width;
  const rightEdge = view.x + (placed.x + NODE_W) * view.k;
  const limit = canvasWidth - drawerWidth - 24;
  if (rightEdge > limit) {
    view.x -= rightEdge - limit;
    applyTransform();
  }
}

function closeDrawer() {
  dom.drawer.hidden = true;
}

function chip(text, kind) {
  return el('span', { className: `chip${kind ? ` ${kind}` : ''}`, text });
}

function kv(pairs) {
  const dl = el('dl', { className: 'kv' });
  for (const [key, value, mono] of pairs) {
    if (value === null || value === undefined || value === '') continue;
    dl.append(el('dt', { text: key }));
    dl.append(el('dd', { className: mono ? 'mono' : '', text: value }));
  }
  return dl;
}

function section(title, ...children) {
  return el('div', { className: 'dv-section' }, [el('h4', { text: title }), ...children]);
}

function deviceView(node) {
  const d = node.device;
  const cat = CATEGORIES[d.category] || CATEGORIES.unknown;
  const wrap = el('div');

  wrap.append(el('div', { className: 'dv-head' }, [
    el('div', { className: 'dv-icon', text: node.icon || cat.icon }),
    el('div', {}, [
      el('div', { className: 'dv-title', text: node.label }),
      el('div', { className: 'dv-ip mono', text: d.ip }),
    ]),
  ]));

  const chips = el('div', { className: 'chips' }, [
    chip(cat.label, 'accent'),
    d.confidence && d.confidence !== 'none' ? chip(`${d.confidence} confidence`, d.confidence === 'high' ? 'good' : '') : null,
    d.isGateway ? chip('gateway', 'warn') : null,
    d.isSelf ? chip('this machine', 'good') : null,
    d.ports.length ? chip(`${d.ports.length} open port${d.ports.length === 1 ? '' : 's'}`) : chip('no open ports found'),
  ].filter(Boolean));
  wrap.append(chips);

  wrap.append(section('Identity', kv([
    ['IP', d.ip, true],
    ['MAC', d.mac || 'unknown', true],
    ['Vendor', d.vendor || 'unknown'],
    ['Hostname', d.hostname || '—'],
    ['Name via', d.nameSource || '—'],
    ['OS guess', d.os ? `${d.os}${d.osAccuracy ? ` (${d.osAccuracy}%)` : ''}` : '—'],
  ])));

  wrap.append(section('Network', kv([
    ['Subnet', d.subnet || '—', true],
    ['Interface', d.iface || '—'],
    ['Latency', d.rttMs != null ? `${d.rttMs.toFixed(1)} ms` : '—'],
    ['Hops', d.hops != null ? String(d.hops) : '—'],
    ['Found via', d.discoveredBy || '—'],
    ['Uptime', d.uptimeSeconds ? `${Math.round(d.uptimeSeconds / 3600)} h` : '—'],
  ])));

  if (d.ports.length) {
    const table = el('table', { className: 'ports' });
    const head = el('tr', {}, [el('th', { text: 'Port' }), el('th', { text: 'Service' }), el('th', { text: 'Product' })]);
    table.append(el('thead', {}, [head]));
    const tbody = el('tbody');
    for (const p of d.ports) {
      tbody.append(el('tr', {}, [
        el('td', { text: `${p.port}/${p.protocol}` }),
        el('td', { text: p.label || p.service || '—' }),
        el('td', { text: [p.product, p.version].filter(Boolean).join(' ') || '—' }),
      ]));
    }
    table.append(tbody);
    wrap.append(section('Open ports', table));
  }

  const webPorts = d.ports.filter((p) => [80, 443, 8080, 8443, 8006, 5000, 32400].includes(p.port));
  if (webPorts.length) {
    const links = el('div', { className: 'dv-links' });
    for (const p of webPorts) {
      const scheme = [443, 8443].includes(p.port) ? 'https' : 'http';
      const href = `${scheme}://${d.ip}${[80, 443].includes(p.port) ? '' : `:${p.port}`}`;
      const a = el('a', { text: `${scheme}://${d.ip}:${p.port}`, attrs: { href, target: '_blank', rel: 'noreferrer noopener' } });
      links.append(a);
    }
    wrap.append(section('Web interfaces', links));
  }

  if (d.reasons?.length) {
    const ul = el('ul', { className: 'reasons' });
    for (const r of d.reasons) ul.append(el('li', { text: r }));
    wrap.append(section('Why this type', ul));
  }

  if (d.hostnames?.length > 1) {
    wrap.append(section('All names', el('div', { className: 'mono', text: d.hostnames.join(', ') })));
  }

  return wrap;
}

function containerView(node) {
  const wrap = el('div');
  wrap.append(el('div', { className: 'dv-head' }, [
    el('div', { className: 'dv-icon', text: node.icon || '•' }),
    el('div', {}, [
      el('div', { className: 'dv-title', text: node.label }),
      el('div', { className: 'dv-ip mono', text: node.sublabel || '' }),
    ]),
  ]));

  if (node.hop) {
    wrap.append(section('Hop', kv([
      ['Address', node.hop.ip || 'no reply', true],
      ['TTL', String(node.hop.ttl)],
      ['RTT', node.hop.rtt != null ? `${node.hop.rtt} ms` : '—'],
    ])));
  }

  const devices = [];
  eachNode(node, (n) => { if (n.kind === 'device') devices.push(n); });
  if (devices.length) {
    const table = el('table', { className: 'ports' });
    table.append(el('thead', {}, [el('tr', {}, [el('th', { text: 'IP' }), el('th', { text: 'Device' })])]));
    const tbody = el('tbody');
    for (const d of devices.slice(0, 200)) {
      tbody.append(el('tr', {}, [
        el('td', { text: d.ip || '' }),
        el('td', { text: d.label }),
      ]));
    }
    table.append(tbody);
    wrap.append(section(`${devices.length} device${devices.length === 1 ? '' : 's'}`, table));
  } else {
    wrap.append(el('p', { className: 'hint-empty', text: 'Nothing under this node.' }));
  }
  return wrap;
}

/* -------------------------------------------------------------- side panels */

function renderSidebar() {
  const m = state.model?.meta;
  dom.stats.replaceChildren();
  dom.legend.replaceChildren();
  dom.warnings.replaceChildren();

  if (!m) {
    dom['brand-sub'].textContent = 'no scan loaded';
    dom['meta-line'].textContent = '';
    dom['warnings-block'].hidden = true;
    return;
  }

  const when = new Date(m.scannedAt);
  dom['brand-sub'].textContent = `${m.deviceCount} devices · ${when.toLocaleTimeString()}`;

  const subnets = state.model.subnets.filter((s) => s.scannable).length;
  const stats = [
    [m.deviceCount, 'devices'],
    [subnets, subnets === 1 ? 'subnet' : 'subnets'],
    [`${(m.durationMs / 1000).toFixed(1)}s`, 'scan time'],
    [m.method === 'nmap' ? `nmap ${m.nmapVersion || ''}`.trim() : 'ping sweep', 'method'],
  ];
  for (const [value, label] of stats) {
    dom.stats.append(el('div', { className: 'stat' }, [
      el('b', { text: value }),
      el('span', { text: label }),
    ]));
  }

  const counts = new Map();
  for (const d of state.model.devices) counts.set(d.category, (counts.get(d.category) || 0) + 1);
  const order = Object.entries(CATEGORIES).sort((a, b) => a[1].order - b[1].order);
  for (const [key, meta] of order) {
    const count = counts.get(key) || 0;
    if (!count) continue;
    const li = el('li', { className: state.catFilter.has(key) ? 'active' : '' }, [
      el('span', { className: 'swatch', attrs: { style: `background:var(--cat-${key})` } }),
      el('span', { text: `${meta.icon} ${meta.label}` }),
      el('span', { className: 'count', text: String(count) }),
    ]);
    li.addEventListener('click', () => {
      if (state.catFilter.has(key)) state.catFilter.delete(key);
      else state.catFilter.add(key);
      dom['clear-filter'].hidden = state.catFilter.size === 0;
      renderSidebar();
      rebuild({ keepView: false });
    });
    dom.legend.append(li);
  }

  dom['warnings-block'].hidden = !m.warnings?.length;
  for (const w of m.warnings || []) dom.warnings.append(el('li', { text: w }));

  dom['meta-line'].textContent = [
    `profile ${m.profile}`,
    m.privileged ? 'privileged' : 'unprivileged',
    m.oui?.entries ? `${m.oui.entries.toLocaleString()} MAC prefixes` : null,
    when.toLocaleString(),
  ].filter(Boolean).join(' · ');
}

/* ---------------------------------------------------------------- data i/o */

async function loadModel({ fit = true } = {}) {
  const res = await fetch('/api/topology');
  if (!res.ok) {
    dom.empty.hidden = false;
    return;
  }
  state.model = await res.json();
  dom.empty.hidden = true;
  state.tree = buildTree(state.model, { groupBy: state.groupBy });
  autoCollapse();
  renderSidebar();
  rebuild({ keepView: !fit });
  if (fit && activeView === 'topology') fitToView();
}

async function startScan() {
  if (state.scanning) return;
  const targetRaw = dom.target.value.trim();
  const payload = {
    profile: dom.profile.value,
    sudo: dom.sudo.checked,
  };
  if (targetRaw) payload.targets = targetRaw.split(/[\s,]+/).filter(Boolean);

  setScanning(true, 'requesting scan…');
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    setScanning(false);
    dom['progress-text'].textContent = info.reason || 'scan could not start';
    dom.progress.hidden = false;
  }
}

function setScanning(scanning, message) {
  state.scanning = scanning;
  dom.scan.disabled = scanning;
  dom['empty-scan'].disabled = scanning;
  dom.scan.textContent = scanning ? 'Scanning…' : 'Run scan';
  dom.progress.hidden = !scanning;
  if (message) dom['progress-text'].textContent = message;
  if (!scanning) dom['bar-fill'].style.width = '0%';
}

function connectEvents() {
  const source = new EventSource('/api/events');
  source.addEventListener('message', (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch { return; }

    switch (data.type) {
      case 'started':
        setScanning(true, 'starting…');
        break;
      case 'phase':
      case 'names-done':
        setScanning(true, data.message || data.phase);
        break;
      case 'progress': {
        const pct = typeof data.percent === 'number' ? data.percent : null;
        if (pct !== null) dom['bar-fill'].style.width = `${Math.min(100, pct)}%`;
        const bits = [data.task || data.phase];
        if (pct !== null) bits.push(`${pct.toFixed(0)}%`);
        if (data.remainingSeconds) bits.push(`~${data.remainingSeconds}s left`);
        if (data.found != null) bits.push(`${data.found} found`);
        dom['progress-text'].textContent = bits.join(' · ');
        break;
      }
      case 'model':
        loadModel({ fit: true });
        break;
      case 'error':
        setScanning(false);
        dom.progress.hidden = false;
        dom['progress-text'].textContent = `failed: ${data.message}`;
        break;
      case 'idle':
        setScanning(false);
        break;
      default:
        break;
    }
  });
  source.addEventListener('error', () => { /* EventSource retries on its own */ });
}

function exportSvg() {
  exportSvgFile(dom.map, contentBounds(), { filename: 'topology.svg' });
}

/* -------------------------------------------------------------------- views */

const views = {
  topology: {
    fit: fitToView,
    show: canvas.fitIfNeeded,
    closeDrawer,
    focusSearch: () => dom.search.focus(),
  },
  traffic: null, // both created below, once the DOM they need exists
  heatmap: null,
};
let activeView = 'topology';

function showView(name) {
  if (!views[name] || activeView === name) return;
  const previous = activeView;
  activeView = name;
  for (const tab of document.querySelectorAll('.tab')) {
    const on = tab.dataset.view === name;
    tab.classList.toggle('active', on);
    tab.setAttribute('aria-selected', String(on));
  }
  for (const section of document.querySelectorAll('.view')) {
    section.hidden = section.dataset.view !== name;
  }
  for (const pane of document.querySelectorAll('.pane')) {
    // A pane may serve several views: the capture controls are shared by the
    // traffic map and the heatmap, which are two readings of one capture.
    pane.hidden = !(pane.dataset.pane || '').split(/\s+/).includes(name);
  }
  views[previous]?.hide?.();
  // A hidden view has no layout and so cannot measure itself; show() fits only
  // when the frame is actually stale, leaving an existing pan/zoom alone.
  views[name].show?.();
}

/** Jump from a traffic endpoint to the same device in the topology tree. */
function showInTopology(ip) {
  showView('topology');
  if (!state.model) return;
  state.query = '';
  dom.search.value = '';
  state.collapsed.clear(); // the device may sit inside a collapsed group
  state.selectedId = `dev:${ip}`; // topology.js keys device nodes this way
  rebuild({ keepView: false });
  const node = state.nodes.find((candidate) => candidate.id === state.selectedId);
  if (node) {
    fitToView();
    openDrawer(node);
  }
}

/* ------------------------------------------------------------------ wire up */

function bind() {
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => showView(tab.dataset.view));
  }

  dom.scan.addEventListener('click', startScan);
  dom['empty-scan'].addEventListener('click', startScan);
  dom.fit.addEventListener('click', fitToView);
  dom['zoom-in'].addEventListener('click', () => zoomBy(1.25));
  dom['zoom-out'].addEventListener('click', () => zoomBy(0.8));
  dom.expand.addEventListener('click', () => setAllCollapsed(false));
  dom.collapse.addEventListener('click', () => setAllCollapsed(true));
  dom['drawer-close'].addEventListener('click', closeDrawer);
  dom['export-svg'].addEventListener('click', exportSvg);
  dom['export-json'].addEventListener('click', () => {
    if (state.model) download('topology.json', new Blob([JSON.stringify(state.model, null, 2)], { type: 'application/json' }));
  });
  dom['clear-filter'].addEventListener('click', () => {
    state.catFilter.clear();
    dom['clear-filter'].hidden = true;
    renderSidebar();
    rebuild({ keepView: false });
  });

  dom.group.addEventListener('change', () => {
    state.groupBy = dom.group.value;
    state.collapsed.clear();
    state.tree = state.model ? buildTree(state.model, { groupBy: state.groupBy }) : null;
    autoCollapse();
    rebuild({ keepView: false });
  });

  let searchTimer = null;
  dom.search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = dom.search.value;
      if (state.query.trim()) state.collapsed.clear();
      rebuild({ keepView: false });
    }, 140);
  });

  window.addEventListener('keydown', (e) => {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) {
      if (e.key === 'Escape') e.target.blur();
      return;
    }
    const current = views[activeView];
    if (e.key === '/') { e.preventDefault(); current.focusSearch?.(); }
    else if (e.key === 'Escape') current.closeDrawer?.();
    else if (e.key === 'f') current.fit?.();
    else if (e.key === 't') {
      const order = ['topology', 'traffic', 'heatmap'];
      showView(order[(order.indexOf(activeView) + 1) % order.length]);
    }
    else if (activeView === 'topology' && e.key === 'e') setAllCollapsed(false);
    else if (activeView === 'topology' && e.key === 'c') setAllCollapsed(true);
  });

  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => views[activeView]?.fit?.(), 160);
  });
}

// One store, so the two traffic views share a capture, an event stream and a
// single set of start/stop controls.
const trafficStore = createTrafficStore();
// Owns the sidebar capture block, which both traffic views share and which must
// keep updating whichever tab is on screen.
const captureControls = createCaptureControls({ store: trafficStore });

views.traffic = createTrafficView({
  store: trafficStore,
  controls: captureControls,
  getModel: () => state.model,
  onShowInTopology: showInTopology,
});

views.heatmap = createHeatmapView({
  store: trafficStore,
  getModel: () => state.model,
  onShowInTopology: showInTopology,
  onShowInTraffic: (nodeId) => {
    showView('traffic');
    views.traffic.select?.(nodeId);
  },
});

bind();
connectEvents();
loadModel().catch(() => { dom.empty.hidden = false; });
