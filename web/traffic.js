import {
  buildFlowGraph,
  TRAFFIC_CLASSES,
  CLASS_ORDER,
  formatWeight,
  formatRate,
  formatCount,
  weightNoun,
} from '/shared/flows.js';
import { CATEGORIES } from '/shared/classify.js';
import { createCanvas, exportSvgFile, download } from '/canvas.js';

/**
 * Traffic map front-end: a force-directed graph of who is talking to whom,
 * rebuilt from a snapshot once a second while a capture runs.
 *
 * The layout runs in two passes so a live update does not rebuild the DOM 60
 * times a second: renderStructure() creates elements when the set of nodes and
 * edges changes, and renderPositions() only moves them while the simulation
 * settles.
 *
 * As in the topology view, every string that came off the network is written
 * through textContent — hostnames and process names are not ours.
 */

const SVG_NS = 'http://www.w3.org/2000/svg';
const MAX_NODES = 200;   // beyond this the O(n²) repulsion and the map both suffer
const LABEL_LIMIT = 28;  // nodes that always carry a visible label

export function createTrafficView({ onShowInTopology = () => {}, getModel = () => null } = {}) {
  const $ = (id) => document.getElementById(id);
  const dom = {};
  for (const id of [
    't-map', 't-viewport', 't-edges', 't-nodes', 't-canvas', 't-empty', 't-empty-start',
    't-search', 't-grouping', 't-live', 't-fit', 't-zoom-in', 't-zoom-out',
    't-export-svg', 't-export-json', 't-window', 't-sudo', 't-iface', 't-start',
    't-status', 't-stats', 't-vantage', 't-classes', 't-clear-class', 't-talkers',
    't-notes', 't-notes-block', 't-drawer', 't-drawer-body', 't-drawer-close',
    't-progress', 't-bar-fill', 't-empty-progress', 't-empty-bar', 't-empty-status',
    't-empty-detail', 't-empty-title', 't-empty-blurb', 't-empty-fine', 't-empty-clear',
  ]) dom[id] = $(id);

  const state = {
    snapshot: null,
    graph: { nodes: [], edges: [], unit: 'bytes' },
    running: false,
    paused: false,
    query: '',
    groupInternet: true,
    classFilter: new Set(),
    selected: null,  // {type: 'node'|'edge', id}
    hoverId: null,
    visible: false,
    warnings: [],
    status: 'idle',
    pending: false,        // a start/stop request is in flight
    startedAt: null,       // wall clock the running capture began
    captureSeconds: 0,     // requested window; 0 means "until stopped"
    everCaptured: false,   // a capture has finished, so "nothing seen" is news
    ticker: null,
  };

  /* ------------------------------------------------------------- simulation */

  const sim = {
    nodes: new Map(), // id -> {id, x, y, vx, vy, r, pinned}
    edges: [],
    alpha: 0,
    frame: null,
    signature: '', // node/edge ids, to tell a reshape from a mere reweighting
  };

  function bounds() {
    const list = [...sim.nodes.values()];
    if (!list.length) return { minX: -200, minY: -150, maxX: 200, maxY: 150 };
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of list) {
      const pad = n.r + 46; // leave room for the label under each node
      minX = Math.min(minX, n.x - pad);
      minY = Math.min(minY, n.y - pad);
      maxX = Math.max(maxX, n.x + pad);
      maxY = Math.max(maxY, n.y + pad);
    }
    return { minX, minY, maxX, maxY };
  }

  const canvas = createCanvas({
    svg: dom['t-map'],
    viewport: dom['t-viewport'],
    container: dom['t-canvas'],
    getBounds: bounds,
    onBackgroundClick: () => {
      state.selected = null;
      closeDrawer();
      applyFocus();
    },
    onNodeDrag: {
      hitTest: (event) => {
        const group = event.target.closest?.('[data-node-id]');
        const node = group && sim.nodes.get(group.dataset.nodeId);
        return node || null;
      },
      start: (node) => {
        node.dragging = true;
      },
      move: (node, point) => {
        node.x = point.x;
        node.y = point.y;
        node.vx = 0;
        node.vy = 0;
        sim.alpha = Math.max(sim.alpha, 0.25);
        renderPositions();
        ensureTicking();
      },
      end: (node, moved) => {
        node.dragging = false;
        // A drag pins the node where it was dropped; a click does not.
        if (moved) node.pinned = true;
        renderStructureClasses();
      },
    },
  });

  /**
   * One step of a plain spring/repulsion model. No quadtree: MAX_NODES keeps
   * the pair count low enough that the simple version is fast and predictable.
   */
  function tick() {
    const nodes = [...sim.nodes.values()];
    const n = nodes.length;
    if (!n) return;

    for (const node of nodes) {
      node.fx = 0;
      node.fy = 0;
    }

    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) {
          // Perfectly coincident nodes have no direction to separate along;
          // nudge them apart deterministically by index instead of randomly.
          dx = (j - i) * 0.7;
          dy = (i % 3) - 1 + 0.3;
          d2 = dx * dx + dy * dy;
        }
        const min = a.r + b.r + 26;
        const force = (2400 + min * 40) / Math.max(d2, min * min * 0.35);
        const d = Math.sqrt(d2);
        const ux = dx / d;
        const uy = dy / d;
        a.fx -= ux * force;
        a.fy -= uy * force;
        b.fx += ux * force;
        b.fy += uy * force;
      }
    }

    for (const edge of sim.edges) {
      const a = sim.nodes.get(edge.source);
      const b = sim.nodes.get(edge.target);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      // Busier conversations sit closer together, so weight reads as proximity
      // as well as stroke width.
      const target = a.r + b.r + 150 - 70 * edge.norm;
      const force = (d - target) * (0.012 + 0.03 * edge.norm);
      const ux = (dx / d) * force;
      const uy = (dy / d) * force;
      a.fx += ux;
      a.fy += uy;
      b.fx -= ux;
      b.fy -= uy;
    }

    for (const node of nodes) {
      // This machine is the vantage point; holding it near the middle keeps the
      // picture oriented the same way from one capture to the next.
      const pull = node.kind === 'self' ? 0.055 : 0.006;
      node.fx -= node.x * pull;
      node.fy -= node.y * pull;

      if (node.pinned || node.dragging) {
        node.vx = 0;
        node.vy = 0;
        continue;
      }
      node.vx = (node.vx + node.fx) * 0.82;
      node.vy = (node.vy + node.fy) * 0.82;
      const speed = Math.hypot(node.vx, node.vy);
      const cap = 40;
      if (speed > cap) {
        node.vx = (node.vx / speed) * cap;
        node.vy = (node.vy / speed) * cap;
      }
      node.x += node.vx * sim.alpha;
      node.y += node.vy * sim.alpha;
    }

    sim.alpha *= 0.984;
  }

  function ensureTicking() {
    if (sim.frame !== null) return;
    const step = () => {
      sim.frame = null;
      if (!state.visible || sim.alpha < 0.004) {
        sim.alpha = 0;
        return;
      }
      tick();
      renderPositions();
      sim.frame = requestAnimationFrame(step);
    };
    sim.frame = requestAnimationFrame(step);
  }

  function stopTicking() {
    if (sim.frame !== null) cancelAnimationFrame(sim.frame);
    sim.frame = null;
  }

  /* ------------------------------------------------------------ data -> sim */

  function rebuild({ fit = false } = {}) {
    const graph = buildFlowGraph({
      snapshot: state.snapshot,
      model: getModel(),
      options: {
        groupInternet: state.groupInternet,
        classFilter: state.classFilter,
        query: state.query,
      },
    });

    // Keep the busiest nodes; a hundred CDN endpoints add nothing but hairball.
    let nodes = graph.nodes;
    let hidden = 0;
    if (nodes.length > MAX_NODES) {
      hidden = nodes.length - MAX_NODES;
      nodes = nodes.slice(0, MAX_NODES);
      const kept = new Set(nodes.map((node) => node.id));
      graph.edges = graph.edges.filter((edge) => kept.has(edge.source) && kept.has(edge.target));
    }
    graph.nodes = nodes;
    graph.hiddenNodes = hidden;
    state.graph = graph;

    // Settled before rendering, so a later failure cannot leave the overlay
    // contradicting what is on the map.
    renderEmptyState();

    const maxNodeWeight = Math.max(1, ...nodes.map((node) => node.bytes));
    const maxEdgeWeight = Math.max(1, ...graph.edges.map((edge) => edge.bytes));

    const live = new Set();
    for (const node of nodes) {
      live.add(node.id);
      let entry = sim.nodes.get(node.id);
      if (!entry) {
        // Seed next to the busiest neighbour already placed, so a new node
        // arrives roughly where it belongs instead of flying in from centre.
        const near = graph.edges.find((edge) => (edge.source === node.id && sim.nodes.has(edge.target))
          || (edge.target === node.id && sim.nodes.has(edge.source)));
        const anchor = near
          ? sim.nodes.get(near.source === node.id ? near.target : near.source)
          : null;
        const spread = 110 + sim.nodes.size * 1.5;
        const angle = (sim.nodes.size * 2.39996) % (Math.PI * 2); // golden angle
        entry = {
          id: node.id,
          x: (anchor?.x || 0) + Math.cos(angle) * (anchor ? 70 : spread),
          y: (anchor?.y || 0) + Math.sin(angle) * (anchor ? 70 : spread),
          vx: 0,
          vy: 0,
          pinned: false,
        };
        sim.nodes.set(node.id, entry);
      }
      entry.kind = node.kind;
      entry.data = node;
      entry.r = 7 + 15 * Math.sqrt(node.bytes / maxNodeWeight);
    }
    for (const id of [...sim.nodes.keys()]) if (!live.has(id)) sim.nodes.delete(id);

    sim.edges = graph.edges.map((edge) => ({
      ...edge,
      norm: Math.sqrt(edge.bytes / maxEdgeWeight),
    }));

    // A snapshot arrives every second, and re-heating the simulation on each one
    // would leave the map permanently jiggling and the CPU permanently busy. A
    // snapshot that only moves the numbers needs no layout at all — radii and
    // stroke widths are set directly — so the layout runs only when the set of
    // nodes or edges actually changes. In a steady state the map holds still.
    const signature = `${[...sim.nodes.keys()].sort().join(',')}|${sim.edges.map((edge) => edge.id).sort().join(',')}`;
    const reshaped = signature !== sim.signature;
    sim.signature = signature;
    if (nodes.length && reshaped) sim.alpha = Math.max(sim.alpha, 0.45);
    renderStructure();
    if (fit) {
      // Let the layout settle before framing it, or the fit is of a hairball.
      settle(140);
      canvas.fitToView();
    }
    ensureTicking();
    renderSidebar();
  }

  /**
   * The overlay has to say which kind of empty this is. Conflating "nothing was
   * captured" with "your search matched nothing" made a running capture with
   * plenty of data look permanently dead, with no hint that a filter was the
   * cause — so the filtered case gets its own message and a way out.
   */
  function renderEmptyState() {
    const captured = (state.snapshot?.endpoints || []).length > 0;
    const filtering = Boolean(state.query.trim()) || state.classFilter.size > 0;
    const active = state.running || state.pending;
    const shown = state.graph.nodes.length;

    dom['t-empty-clear'].hidden = true;
    if (shown > 0) {
      dom['t-empty'].hidden = true;
      return;
    }
    dom['t-empty'].hidden = false;

    if (captured && filtering) {
      dom['t-empty-title'].textContent = 'Nothing matches';
      dom['t-empty-blurb'].textContent = state.query.trim() && state.classFilter.size
        ? 'The capture has traffic, but no endpoint matches this search and traffic-type filter.'
        : state.query.trim()
          ? 'The capture has traffic, but no endpoint matches this search.'
          : 'The capture has traffic, but none of it is of the selected type.';
      dom['t-empty-clear'].hidden = false;
      dom['t-empty-progress'].hidden = true;
      dom['t-empty-fine'].hidden = true;
      dom['t-empty-start'].hidden = true;
      return;
    }

    dom['t-empty-start'].hidden = false;
    if (active) {
      dom['t-empty-title'].textContent = 'Listening…';
      dom['t-empty-blurb'].textContent =
        'Devices appear here as soon as they send something this capture point can see.';
      dom['t-empty-progress'].hidden = false;
      dom['t-empty-fine'].hidden = true;
    } else if (state.everCaptured) {
      dom['t-empty-title'].textContent = 'No traffic seen';
      dom['t-empty-blurb'].textContent =
        'Nothing crossed this capture point during the window. On a switched network that is '
        + 'normal for a quiet moment — try a longer window, or enable sudo to see other devices.';
      dom['t-empty-progress'].hidden = true;
      dom['t-empty-fine'].hidden = false;
    } else {
      dom['t-empty-title'].textContent = 'No traffic captured yet';
      dom['t-empty-blurb'].textContent =
        'Start a capture to see which devices are actually talking, and about what. '
        + "With sudo it reads real packets and byte counts; without it, only this machine's own connections.";
      dom['t-empty-progress'].hidden = true;
      dom['t-empty-fine'].hidden = false;
    }
  }

  function settle(steps) {
    const saved = sim.alpha;
    sim.alpha = Math.max(saved, 0.9);
    for (let i = 0; i < steps; i++) tick();
    sim.alpha = Math.max(0.05, saved * 0.5);
    renderPositions();
  }

  /* ------------------------------------------------------------- rendering */

  const els = { nodes: new Map(), edges: new Map() };

  function svg(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v !== null && v !== undefined) node.setAttribute(k, String(v));
    }
    return node;
  }

  function classColor(key) {
    return TRAFFIC_CLASSES[key] ? `var(--flow-${key})` : 'var(--flow-other)';
  }

  function nodeColor(node) {
    if (node.kind === 'self') return 'var(--cat-self)';
    if (node.kind === 'internet') return 'var(--cat-hop)';
    if (node.kind === 'multicast' || node.kind === 'broadcast') return 'var(--flow-discovery)';
    if (node.category && CATEGORIES[node.category]) return `var(--cat-${node.category})`;
    return 'var(--cat-unknown)';
  }

  function renderStructure() {
    const edgeIds = new Set(sim.edges.map((edge) => edge.id));
    for (const [id, el] of els.edges) {
      if (!edgeIds.has(id)) {
        el.remove();
        els.edges.delete(id);
      }
    }
    for (const edge of sim.edges) {
      let line = els.edges.get(edge.id);
      if (!line) {
        line = svg('line', { class: 'flow-edge' });
        line.dataset.edgeId = edge.id;
        line.addEventListener('click', (event) => {
          event.stopPropagation();
          if (canvas.wasDrag()) return;
          select({ type: 'edge', id: edge.id });
        });
        line.addEventListener('pointerenter', () => setHover(edge.id));
        line.addEventListener('pointerleave', () => setHover(null));
        dom['t-edges'].append(line);
        els.edges.set(edge.id, line);
      }
      line.setAttribute('stroke', classColor(edge.dominant));
      line.setAttribute('stroke-width', (1.1 + 5.4 * edge.norm).toFixed(2));
    }

    const labelled = new Set(state.graph.nodes.slice(0, LABEL_LIMIT).map((node) => node.id));
    const nodeIds = new Set(sim.nodes.keys());
    for (const [id, el] of els.nodes) {
      if (!nodeIds.has(id)) {
        el.group.remove();
        els.nodes.delete(id);
      }
    }
    for (const entry of sim.nodes.values()) {
      let el = els.nodes.get(entry.id);
      if (!el) {
        const group = svg('g', { class: 'flow-node' });
        group.dataset.nodeId = entry.id;
        const halo = svg('circle', { class: 'halo' });
        const disc = svg('circle', { class: 'disc' });
        const icon = svg('text', { class: 'icon', 'text-anchor': 'middle' });
        const label = svg('text', { class: 'label', 'text-anchor': 'middle' });
        const sub = svg('text', { class: 'sub', 'text-anchor': 'middle' });
        group.append(halo, disc, icon, label, sub);
        group.addEventListener('click', (event) => {
          event.stopPropagation();
          if (canvas.wasDrag()) return;
          select({ type: 'node', id: entry.id });
        });
        group.addEventListener('dblclick', (event) => {
          event.stopPropagation();
          entry.pinned = false;
          sim.alpha = Math.max(sim.alpha, 0.3);
          renderStructureClasses();
          ensureTicking();
        });
        group.addEventListener('pointerenter', () => setHover(entry.id));
        group.addEventListener('pointerleave', () => setHover(null));
        dom['t-nodes'].append(group);
        el = { group, halo, disc, icon, label, sub };
        els.nodes.set(entry.id, el);
      }

      const data = entry.data;
      el.disc.setAttribute('r', entry.r.toFixed(1));
      el.disc.setAttribute('fill', nodeColor(data));
      el.halo.setAttribute('r', (entry.r + 5).toFixed(1));
      el.icon.setAttribute('font-size', Math.min(18, Math.max(9, entry.r * 1.05)).toFixed(1));
      el.icon.setAttribute('y', (entry.r * 0.36).toFixed(1));
      el.icon.textContent = entry.r >= 10 ? (data.icon || '•') : '';
      el.label.setAttribute('y', (entry.r + 15).toFixed(1));
      el.sub.setAttribute('y', (entry.r + 26).toFixed(1));
      el.label.textContent = truncate(data.label, 24);
      el.sub.textContent = `${formatWeight(data.bytes, state.graph.unit)}${state.graph.unit === 'bytes' ? '' : ' conn'}`;
      el.group.classList.toggle('unlabelled', !labelled.has(entry.id));
    }

    renderStructureClasses();
    renderPositions();
  }

  /** Classes that depend on selection/hover/pin rather than on the data. */
  function renderStructureClasses() {
    for (const [id, el] of els.nodes) {
      const entry = sim.nodes.get(id);
      el.group.classList.toggle('pinned', Boolean(entry?.pinned));
      el.group.classList.toggle('matched', Boolean(entry?.data?.matched));
    }
    applyFocus();
  }

  function renderPositions() {
    for (const [id, el] of els.nodes) {
      const entry = sim.nodes.get(id);
      if (!entry) continue;
      el.group.setAttribute('transform', `translate(${entry.x.toFixed(1)},${entry.y.toFixed(1)})`);
    }
    for (const edge of sim.edges) {
      const line = els.edges.get(edge.id);
      const a = sim.nodes.get(edge.source);
      const b = sim.nodes.get(edge.target);
      if (!line || !a || !b) continue;
      line.setAttribute('x1', a.x.toFixed(1));
      line.setAttribute('y1', a.y.toFixed(1));
      line.setAttribute('x2', b.x.toFixed(1));
      line.setAttribute('y2', b.y.toFixed(1));
    }
  }

  /** Dim everything not touching the focused node or edge. */
  function applyFocus() {
    const focusId = state.hoverId || (state.selected ? state.selected.id : null);
    const map = dom['t-map'];
    if (!focusId) {
      map.classList.remove('has-focus');
      for (const el of els.nodes.values()) el.group.classList.remove('focus', 'faded');
      for (const line of els.edges.values()) line.classList.remove('focus', 'faded');
      return;
    }

    const near = new Set([focusId]);
    for (const edge of sim.edges) {
      if (edge.id === focusId) {
        near.add(edge.source);
        near.add(edge.target);
      } else if (edge.source === focusId) {
        near.add(edge.target);
      } else if (edge.target === focusId) {
        near.add(edge.source);
      }
    }

    map.classList.add('has-focus');
    for (const [id, el] of els.nodes) {
      const active = near.has(id);
      el.group.classList.toggle('focus', active);
      el.group.classList.toggle('faded', !active);
    }
    for (const edge of sim.edges) {
      const line = els.edges.get(edge.id);
      if (!line) continue;
      const active = edge.id === focusId || edge.source === focusId || edge.target === focusId;
      line.classList.toggle('focus', active);
      line.classList.toggle('faded', !active);
    }
  }

  function setHover(id) {
    if (state.hoverId === id) return;
    state.hoverId = id;
    applyFocus();
  }

  function select(target) {
    state.selected = target;
    applyFocus();
    openDrawer(target);
  }

  /* ---------------------------------------------------------------- drawer */

  function openDrawer(target) {
    const body = dom['t-drawer-body'];
    body.replaceChildren();
    const content = target.type === 'node' ? nodeView(target.id) : edgeView(target.id);
    if (!content) return closeDrawer();
    body.append(content);
    dom['t-drawer'].hidden = false;
    return undefined;
  }

  function closeDrawer() {
    dom['t-drawer'].hidden = true;
  }

  function nodeView(id) {
    const node = state.graph.nodes.find((candidate) => candidate.id === id);
    if (!node) return null;
    const unit = state.graph.unit;
    const wrap = el('div');

    wrap.append(el('div', { className: 'dv-head' }, [
      el('div', { className: 'dv-icon', text: node.icon || '•' }),
      el('div', {}, [
        el('div', { className: 'dv-title', text: node.label }),
        el('div', { className: 'dv-ip mono', text: node.ip || node.sublabel || '' }),
      ]),
    ]));

    const device = node.device;
    wrap.append(el('div', { className: 'chips' }, [
      chip(kindLabel(node.kind), 'accent'),
      device ? chip(CATEGORIES[device.category]?.label || 'device') : null,
      node.identifiedVia ? chip(`matched by ${VIA_LABEL[node.identifiedVia]}`, 'good') : null,
      chip(`${formatCount(node.peerCount)} peer${node.peerCount === 1 ? '' : 's'}`),
      node.filtered ? chip('filtered view', 'warn') : null,
      sim.nodes.get(id)?.pinned ? chip('pinned', 'warn') : null,
    ].filter(Boolean)));

    if (node.series) wrap.append(section('Activity', sparkline(node.series, unit)));

    // Sent/received are always this endpoint's full totals; only the graph's
    // sizing narrows with a filter, so the section says which it is showing.
    wrap.append(section(node.filtered ? 'Volume (all traffic types)' : 'Volume', kv([
      [unit === 'bytes' ? 'Sent' : 'Outbound', formatWeight(node.sentBytes, unit)],
      [unit === 'bytes' ? 'Received' : 'Inbound', formatWeight(node.recvBytes, unit)],
      ['Packets', unit === 'bytes' ? formatCount(node.sentPackets + node.recvPackets) : null],
      ['Shown here', node.filtered ? formatWeight(node.bytes, unit) : null],
      ['Peers', formatCount(node.peerCount)],
      ['Last seen', node.lastSeen ? new Date(node.lastSeen).toLocaleTimeString() : null],
    ])));

    // Identity is worth showing even with no scan match: the hardware address
    // came off the wire, and its OUI still names a maker.
    const observed = (node.macs || []).filter((mac) => mac !== device?.mac);
    if (device || node.mac) {
      wrap.append(section('Identity', kv([
        ['MAC', node.mac || 'unknown', true],
        ['Vendor', node.vendor || 'unknown'],
        ['Hostname', device?.hostname || '—'],
        ['OS guess', device?.os || '—'],
        ['Scanned as', device && device.ip !== node.ip ? device.ip : null, true],
        ['Also seen as', observed.length ? observed.join(', ') : null, true],
      ])));
    }

    if (node.identityReasons?.length) {
      const ul = el('ul', { className: 'reasons' });
      for (const reason of node.identityReasons) ul.append(el('li', { text: reason }));
      wrap.append(section('How this was identified', ul));
    }

    if (device) {
      const jump = el('button', { className: 'link', text: 'Show in topology →' });
      jump.addEventListener('click', () => onShowInTopology(device.ip));
      wrap.append(jump);
    }

    if (node.processes?.length) {
      wrap.append(section('Processes on this machine', chipRow(node.processes)));
    }
    if (node.classes?.length) wrap.append(section('Traffic types', weightTable(node.classes, unit)));
    if (node.ports?.length) wrap.append(section('Top ports', portTable(node.ports, unit)));
    if (node.members?.length > 1) {
      wrap.append(section(
        node.kind === 'internet'
          ? `${node.members.length} grouped endpoints`
          : `${node.members.length} addresses on this device`,
        addressTable(node.members, unit),
      ));
    }
    return wrap;
  }

  function edgeView(id) {
    const edge = state.graph.edges.find((candidate) => candidate.id === id);
    if (!edge) return null;
    const unit = state.graph.unit;
    const label = (nodeId) => state.graph.nodes.find((node) => node.id === nodeId)?.label || nodeId;
    const from = label(edge.source);
    const to = label(edge.target);
    const seconds = Math.max(1, (state.graph.stats?.elapsedMs || 0) / 1000);
    const wrap = el('div');

    wrap.append(el('div', { className: 'dv-head' }, [
      el('div', { className: 'dv-icon', text: '⇄' }),
      el('div', {}, [
        el('div', { className: 'dv-title', text: `${from} ↔ ${to}` }),
        el('div', { className: 'dv-ip', text: TRAFFIC_CLASSES[edge.dominant]?.label || edge.dominant }),
      ]),
    ]));

    wrap.append(el('div', { className: 'chips' }, [
      chip(formatWeight(edge.bytes, unit) + (unit === 'bytes' ? '' : ` ${weightNoun(unit, edge.bytes)}`), 'accent'),
      unit === 'bytes' ? chip(formatRate(edge.bytes / seconds)) : null,
      ...(edge.protocols || []).slice(0, 4).map((p) => chip(p)),
    ].filter(Boolean)));

    if (edge.series) wrap.append(section('Activity', sparkline(edge.series, unit)));

    wrap.append(section('Direction', kv([
      [`${truncate(from, 14)} →`, formatWeight(edge.forwardBytes, unit)],
      [`${truncate(to, 14)} →`, formatWeight(edge.reverseBytes, unit)],
      ['Packets', unit === 'bytes' ? formatCount(edge.packets) : null],
      ['Flows', formatCount(edge.flowCount)],
      ['First seen', edge.firstSeen ? new Date(edge.firstSeen).toLocaleTimeString() : null],
      ['Last seen', edge.lastSeen ? new Date(edge.lastSeen).toLocaleTimeString() : null],
    ])));

    if (edge.processes?.length) {
      wrap.append(section('Processes on this machine', chipRow(edge.processes)));
    }
    if (edge.classes?.length) wrap.append(section('Traffic types', weightTable(edge.classes, unit)));
    if (edge.ports?.length) wrap.append(section('Ports', portTable(edge.ports, unit)));
    if (edge.members?.length > 1) {
      const table = el('table', { className: 'ports' });
      table.append(el('thead', {}, [el('tr', {}, [
        el('th', { text: 'Endpoint pair' }), el('th', { text: unit === 'bytes' ? 'Bytes' : 'Conns' }),
      ])]));
      const tbody = el('tbody');
      for (const member of edge.members.slice(0, 40)) {
        tbody.append(el('tr', {}, [
          el('td', { text: `${member.a} ↔ ${member.b}` }),
          el('td', { text: formatWeight(member.bytes, unit) }),
        ]));
      }
      table.append(tbody);
      wrap.append(section(`${edge.members.length} underlying flows`, table));
    }
    return wrap;
  }

  /* ----------------------------------------------------------- side panels */

  function renderSidebar() {
    const graph = state.graph;
    const stats = graph.stats;
    const unit = graph.unit;

    dom['t-stats'].replaceChildren();
    if (stats) {
      const seconds = Math.max(1, (stats.elapsedMs || 0) / 1000);
      const tiles = [
        [formatWeight(stats.bytes, unit), unit === 'bytes' ? 'total' : 'connections'],
        [unit === 'bytes' ? formatRate(stats.bytes / seconds) : formatCount(stats.packets), unit === 'bytes' ? 'average rate' : 'observations'],
        [formatCount(stats.shownEdges), 'conversations'],
        [formatCount(stats.shownNodes), 'endpoints'],
      ];
      for (const [value, label] of tiles) {
        dom['t-stats'].append(el('div', { className: 'stat' }, [
          el('b', { text: value }),
          el('span', { text: label }),
        ]));
      }
    }

    dom['t-vantage'].replaceChildren();
    const vantage = graph.vantage;
    if (vantage) {
      const ifaces = (vantage.interfaces || []).join(', ');
      dom['t-vantage'].append(el('p', {
        className: 'vantage-method',
        text: vantage.method === 'tcpdump'
          ? `Packet capture on ${ifaces || 'no interface'}`
          : 'Open-connection sampling (no packet capture)',
      }));
      if (vantage.sees) {
        dom['t-vantage'].append(el('p', { className: 'vantage-note', text: vantage.sees }));
      }
    }

    dom['t-classes'].replaceChildren();
    const totals = new Map((graph.classes || []).map((entry) => [entry.key, entry]));
    for (const key of CLASS_ORDER) {
      const entry = totals.get(key);
      if (!entry?.bytes) continue;
      const li = el('li', { className: state.classFilter.has(key) ? 'active' : '' }, [
        el('span', { className: 'swatch', attrs: { style: `background:var(--flow-${key})` } }),
        el('span', { text: TRAFFIC_CLASSES[key]?.label || key }),
        el('span', { className: 'count', text: formatWeight(entry.bytes, unit) }),
      ]);
      li.addEventListener('click', () => {
        if (state.classFilter.has(key)) state.classFilter.delete(key);
        else state.classFilter.add(key);
        dom['t-clear-class'].hidden = state.classFilter.size === 0;
        rebuild();
      });
      dom['t-classes'].append(li);
    }

    dom['t-talkers'].replaceChildren();
    for (const node of graph.nodes.slice(0, 8)) {
      const row = el('li', {}, [
        el('span', { className: 'talker-icon', text: node.icon || '•' }),
        el('span', { className: 'talker-name', text: truncate(node.label, 18) }),
        node.series ? sparkline(node.series, unit, { width: 52, height: 14, bare: true }) : el('span'),
        el('span', { className: 'count', text: formatWeight(node.bytes, unit) }),
      ]);
      row.addEventListener('click', () => select({ type: 'node', id: node.id }));
      dom['t-talkers'].append(row);
    }

    const notes = [...state.warnings];
    if (graph.hiddenNodes) {
      notes.push(`Showing the ${MAX_NODES} busiest endpoints; ${graph.hiddenNodes} quieter ones are not drawn.`);
    }
    if (stats?.truncated?.flows) {
      notes.push(`${stats.truncated.flows} conversations beyond the top 400 are counted in the totals but not drawn.`);
    }
    if (stats?.droppedPackets) {
      notes.push(`${formatCount(stats.droppedPackets)} packets were dropped from the flow table under load.`);
    }
    dom['t-notes'].replaceChildren();
    dom['t-notes-block'].hidden = notes.length === 0;
    for (const note of notes) dom['t-notes'].append(el('li', { text: note }));
  }

  /**
   * Single place that renders capture state onto the controls. `busy` covers
   * both a running capture and a request in flight, because in either case the
   * only safe thing for the popup's button to be is disabled: it shares a
   * handler with the sidebar's, so a second click on "Start capture" would
   * otherwise stop the capture that first click had just started.
   */
  function setStatus(text, busy = state.running) {
    state.status = text;
    const active = busy || state.pending;

    dom['t-status'].textContent = text;

    // The sidebar button stays usable so a running capture can be stopped, but
    // not while a request is unresolved.
    dom['t-start'].textContent = busy ? 'Stop capture' : 'Start capture';
    dom['t-start'].classList.toggle('primary', !busy);
    dom['t-start'].disabled = state.pending;

    dom['t-empty-start'].disabled = active;
    dom['t-empty-start'].textContent = active ? 'Capturing…' : 'Start capture';
    dom['t-empty-status'].textContent = text;
    dom['t-progress'].hidden = !active;

    dom['t-live'].textContent = state.paused ? 'Resume' : 'Pause';
    dom['t-live'].disabled = !state.running;

    renderEmptyState();
    if (active) startTicker();
    else stopTicker();
  }

  /* -------------------------------------------------------------- progress */

  function startTicker() {
    if (state.ticker !== null) return;
    state.ticker = setInterval(renderProgress, 250);
    renderProgress();
  }

  function stopTicker() {
    if (state.ticker !== null) clearInterval(state.ticker);
    state.ticker = null;
    for (const bar of [dom['t-bar-fill'], dom['t-empty-bar']]) {
      bar.classList.remove('indeterminate');
      bar.style.width = '0%';
    }
    dom['t-empty-detail'].textContent = '';
  }

  function renderProgress() {
    const total = state.captureSeconds;
    const elapsed = state.startedAt ? (Date.now() - state.startedAt) / 1000 : 0;
    // A fixed window has a real end to count towards; "until stopped" does not,
    // so the bar cycles rather than claiming a progress it cannot know.
    const indeterminate = !total || !state.startedAt;
    const percent = indeterminate ? 100 : Math.min(100, (elapsed / total) * 100);

    for (const bar of [dom['t-bar-fill'], dom['t-empty-bar']]) {
      bar.classList.toggle('indeterminate', indeterminate);
      bar.style.width = `${percent.toFixed(1)}%`;
    }
    dom['t-empty-detail'].textContent = progressDetail(elapsed, total);
  }

  function progressDetail(elapsed, total) {
    const totals = state.snapshot?.totals;
    const unit = state.graph.unit;
    const bits = [];
    if (totals) {
      bits.push(unit === 'bytes'
        ? `${formatWeight(totals.bytes, unit)} · ${formatCount(totals.packets)} packets`
        : `${formatCount(totals.bytes)} connections`);
      bits.push(`${formatCount(totals.flows)} conversation${totals.flows === 1 ? '' : 's'}`);
    }
    if (state.startedAt) {
      bits.push(total ? `${clock(elapsed)} of ${clock(total)}` : `${clock(elapsed)} elapsed`);
    }
    return bits.join('   ');
  }

  /* ------------------------------------------------------------- data i/o */

  /**
   * Applies a snapshot unless a newer one already landed. The initial fetch and
   * the event stream race on every tab open, and the fetch losing that race
   * used to blank a live map back to the empty state.
   */
  function applySnapshot(snapshot, { fit = false } = {}) {
    const at = snapshot?.window?.now || 0;
    if (!snapshot || at < state.snapshotAt) return false;
    state.snapshot = snapshot;
    state.snapshotAt = at;
    state.warnings = snapshot.vantage?.warnings || state.warnings;
    if (snapshot.vantage?.startedAt) state.startedAt = snapshot.vantage.startedAt;
    if (Number.isFinite(snapshot.vantage?.seconds)) state.captureSeconds = snapshot.vantage.seconds;
    if (state.visible) rebuild({ fit });
    return true;
  }

  async function loadSnapshot({ fit = true } = {}) {
    const res = await fetch('/api/traffic');
    if (!res.ok) return;
    const payload = await res.json();
    if (payload.snapshot) {
      state.running = Boolean(payload.running);
      state.warnings = payload.warnings || [];
      if (payload.running) state.everCaptured = false;
      if (!applySnapshot(payload.snapshot, { fit })) return;
    } else if (state.snapshot) {
      return; // the stream got there first; leave the live map alone
    } else {
      state.running = Boolean(payload.running);
      state.warnings = payload.warnings || [];
      renderSidebar();
      renderEmptyState();
    }
    setStatus(state.running ? 'capturing…' : payload.snapshot ? 'capture stopped' : 'idle');
  }

  async function toggleCapture() {
    if (state.pending) return; // a start or stop is already in flight
    if (state.running) return stopCapture();
    return startCapture();
  }

  async function startCapture() {
    const ifaceRaw = dom['t-iface'].value.trim();
    const seconds = Number(dom['t-window'].value);
    const payload = { seconds, sudo: dom['t-sudo'].checked };
    if (ifaceRaw) payload.ifaces = ifaceRaw.split(/[\s,]+/).filter(Boolean);

    state.pending = true;
    state.captureSeconds = Number.isFinite(seconds) ? seconds : 0;
    state.startedAt = Date.now(); // provisional until the server reports its own
    setStatus('starting…', true);

    let started = false;
    let message = 'capture could not start';
    try {
      const res = await fetch('/api/traffic/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const info = await res.json().catch(() => ({}));
      started = res.ok;
      if (started) {
        // The server's own figures win: it may have clamped the window.
        if (info.vantage?.startedAt) state.startedAt = info.vantage.startedAt;
        if (Number.isFinite(info.vantage?.seconds)) state.captureSeconds = info.vantage.seconds;
        state.running = true;
        message = info.vantage?.method === 'tcpdump'
          ? `capturing on ${(info.vantage.interfaces || []).join(', ') || 'no interface'}…`
          : 'sampling open connections…';
      } else {
        message = info.reason || message;
      }
    } catch {
      /* network error; the default message stands */
    }

    // Cleared before the final render, or the controls would stay disabled.
    state.pending = false;
    if (!started) state.startedAt = null;
    setStatus(message, started);
  }

  async function stopCapture() {
    state.pending = true;
    setStatus('stopping…', true);
    try {
      await fetch('/api/traffic/stop', { method: 'POST' });
    } catch {
      /* the stopped event or the next poll will correct the display */
    }
    state.pending = false;
    state.running = false;
    state.everCaptured = true;
    state.startedAt = null;
    setStatus('capture stopped', false);
  }

  function connectEvents() {
    const source = new EventSource('/api/traffic/events');
    source.addEventListener('message', (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }

      switch (data.type) {
        case 'traffic-started':
          state.running = true;
          state.warnings = data.vantage?.warnings || state.warnings;
          // A client that connects mid-capture learns the window from the
          // event, so its progress bar counts towards the same end.
          if (data.vantage?.startedAt) state.startedAt = data.vantage.startedAt;
          if (Number.isFinite(data.seconds)) state.captureSeconds = data.seconds;
          else if (Number.isFinite(data.vantage?.seconds)) state.captureSeconds = data.vantage.seconds;
          setStatus(data.message || 'capturing…', true);
          break;
        case 'traffic-phase':
          setStatus(data.message || 'capturing…', true);
          break;
        case 'traffic-warning':
          if (!state.warnings.includes(data.message)) state.warnings.push(data.message);
          renderSidebar();
          break;
        case 'traffic-snapshot': {
          if (state.paused) break;
          const first = !state.snapshot;
          state.running = data.snapshot?.vantage?.running ?? state.running;
          applySnapshot(data.snapshot, { fit: first });
          setStatus(state.running ? 'capturing…' : 'capture stopped');
          break;
        }
        case 'traffic-stopped':
          state.running = false;
          state.everCaptured = true;
          state.startedAt = null;
          if (!state.paused) applySnapshot(data.snapshot);
          setStatus(data.message || 'capture stopped', false);
          break;
        case 'traffic-idle':
          state.running = false;
          state.startedAt = null;
          setStatus(state.snapshot ? 'capture stopped' : 'idle', false);
          break;
        default:
          break;
      }
    });
    source.addEventListener('error', () => { /* EventSource retries on its own */ });
  }

  /* ------------------------------------------------------------- wire up */

  dom['t-start'].addEventListener('click', toggleCapture);
  dom['t-empty-start'].addEventListener('click', toggleCapture);
  dom['t-drawer-close'].addEventListener('click', () => {
    state.selected = null;
    closeDrawer();
    applyFocus();
  });
  dom['t-fit'].addEventListener('click', () => canvas.fitToView());
  dom['t-zoom-in'].addEventListener('click', () => canvas.zoomBy(1.25));
  dom['t-zoom-out'].addEventListener('click', () => canvas.zoomBy(0.8));
  dom['t-live'].addEventListener('click', () => {
    state.paused = !state.paused;
    setStatus(state.paused ? 'paused — the map is frozen' : 'capturing…');
  });
  dom['t-grouping'].addEventListener('change', () => {
    state.groupInternet = dom['t-grouping'].value === 'grouped';
    rebuild({ fit: true });
  });
  function clearFilters() {
    state.query = '';
    dom['t-search'].value = '';
    state.classFilter.clear();
    dom['t-clear-class'].hidden = true;
    rebuild({ fit: true });
  }

  dom['t-clear-class'].addEventListener('click', () => {
    state.classFilter.clear();
    dom['t-clear-class'].hidden = true;
    rebuild();
  });
  dom['t-empty-clear'].addEventListener('click', clearFilters);
  dom['t-export-json'].addEventListener('click', () => {
    if (state.snapshot) {
      download('traffic.json', new Blob([JSON.stringify(state.snapshot, null, 2)], { type: 'application/json' }));
    }
  });
  dom['t-export-svg'].addEventListener('click', () => {
    exportSvgFile(dom['t-map'], bounds(), { filename: 'traffic.svg' });
  });

  let searchTimer = null;
  dom['t-search'].addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = dom['t-search'].value;
      rebuild();
    }, 160);
  });

  setStatus('idle', false);
  connectEvents();

  return {
    show() {
      state.visible = true;
      if (!state.snapshot) loadSnapshot({ fit: true }).catch(() => {});
      else {
        // Snapshots kept arriving while the tab was hidden, but rebuild() skips
        // an invisible view, so the map is redrawn on the way in. The frame is
        // only refitted if it went stale, so a pan/zoom survives a tab flip.
        rebuild();
        canvas.fitIfNeeded();
      }
      ensureTicking();
    },
    hide() {
      state.visible = false;
      stopTicking();
    },
    isRunning() {
      return state.running;
    },
    focusSearch() {
      dom['t-search'].focus();
    },
    fit() {
      canvas.fitToView();
    },
    closeDrawer() {
      state.selected = null;
      closeDrawer();
      applyFocus();
    },
  };
}

/* ------------------------------------------------------------------ helpers */

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.className) node.className = opts.className;
  if (opts.text !== undefined) node.textContent = String(opts.text);
  for (const [k, v] of Object.entries(opts.attrs || {})) node.setAttribute(k, String(v));
  for (const child of children) if (child) node.append(child);
  return node;
}

/** Seconds -> m:ss, for the capture countdown. */
function clock(seconds) {
  const whole = Math.max(0, Math.round(seconds));
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`;
}

function truncate(str, max) {
  const s = String(str ?? '');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function chip(text, kind) {
  return el('span', { className: `chip${kind ? ` ${kind}` : ''}`, text });
}

function chipRow(values) {
  return el('div', { className: 'chips' }, values.slice(0, 12).map((value) => chip(value)));
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

const VIA_LABEL = {
  mac: 'MAC address',
  ip: 'IP address',
  name: 'name',
};

function kindLabel(kind) {
  return {
    self: 'this machine',
    local: 'on the LAN',
    internet: 'beyond the gateway',
    multicast: 'multicast group',
    broadcast: 'broadcast',
  }[kind] || kind;
}

function weightTable(rows, unit) {
  const table = el('table', { className: 'ports' });
  table.append(el('thead', {}, [el('tr', {}, [
    el('th', { text: 'Type' }),
    el('th', { text: unit === 'bytes' ? 'Bytes' : 'Conns' }),
  ])]));
  const tbody = el('tbody');
  for (const row of rows) {
    tbody.append(el('tr', {}, [
      el('td', { text: TRAFFIC_CLASSES[row.key]?.label || row.key }),
      el('td', { text: formatWeight(row.bytes, unit) }),
    ]));
  }
  table.append(tbody);
  return table;
}

function portTable(rows, unit) {
  const table = el('table', { className: 'ports' });
  table.append(el('thead', {}, [el('tr', {}, [
    el('th', { text: 'Port' }),
    el('th', { text: 'Service' }),
    el('th', { text: unit === 'bytes' ? 'Bytes' : 'Conns' }),
  ])]));
  const tbody = el('tbody');
  for (const row of rows) {
    tbody.append(el('tr', {}, [
      el('td', { text: String(row.port ?? row.key) }),
      el('td', { text: row.label || '—' }),
      el('td', { text: formatWeight(row.bytes, unit) }),
    ]));
  }
  table.append(tbody);
  return table;
}

function addressTable(members, unit) {
  const table = el('table', { className: 'ports' });
  table.append(el('thead', {}, [el('tr', {}, [
    el('th', { text: 'Address' }),
    el('th', { text: unit === 'bytes' ? 'Bytes' : 'Conns' }),
  ])]));
  const tbody = el('tbody');
  for (const member of members.slice(0, 60)) {
    tbody.append(el('tr', {}, [
      el('td', { text: member.ip }),
      el('td', { text: formatWeight(member.bytes, unit) }),
    ]));
  }
  table.append(tbody);
  return table;
}

/** Inline sparkline of a per-second series. */
function sparkline(series, unit, { width = 300, height = 44, bare = false } = {}) {
  const ns = SVG_NS;
  const values = series || [];
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map((value, index) => {
    const x = index * step;
    const y = height - (value / max) * (height - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const svgEl = document.createElementNS(ns, 'svg');
  svgEl.setAttribute('class', `spark${bare ? ' bare' : ''}`);
  svgEl.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svgEl.setAttribute('preserveAspectRatio', 'none');
  svgEl.setAttribute('width', width);
  svgEl.setAttribute('height', height);

  if (points.length) {
    const area = document.createElementNS(ns, 'path');
    area.setAttribute('class', 'spark-area');
    area.setAttribute('d', `M0,${height} L${points.join(' L')} L${width},${height} Z`);
    svgEl.append(area);
    const line = document.createElementNS(ns, 'path');
    line.setAttribute('class', 'spark-line');
    line.setAttribute('d', `M${points.join(' L')}`);
    svgEl.append(line);
  }

  if (bare) return svgEl;
  const wrap = el('div', { className: 'spark-wrap' });
  wrap.append(svgEl);
  wrap.append(el('div', { className: 'spark-scale' }, [
    el('span', { text: `peak ${formatWeight(max, unit)}/s` }),
    el('span', { text: `${values.length}s window` }),
  ]));
  return wrap;
}
