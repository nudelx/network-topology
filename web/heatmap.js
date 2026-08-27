import {
  buildFlowGraph,
  TRAFFIC_CLASSES,
  formatWeight,
  formatRate,
  formatCount,
  weightNoun,
  visibleBuckets,
  tailOf,
} from '/shared/flows.js';
import { CATEGORIES } from '/shared/classify.js';
import { download } from '/canvas.js';

/**
 * Traffic heatmap: one row per device, one column per second of the capture
 * window, each cell shaded by how much crossed it in that second.
 *
 * This answers the question the force graph cannot — *when* was a device busy.
 * A device that moved 40 MB in one burst and one that trickled the same amount
 * over two minutes are the same size on the map and obviously different here.
 *
 * Ranking by direction is what makes it a top-senders / top-consumers view:
 * `sent` ranks and shades by bytes leaving each device, `received` by bytes
 * arriving. Direction comes from separate ring buffers in the flow model, not
 * from splitting a total after the fact.
 */

const METRICS = {
  total: { label: 'Total', hue: 'var(--accent)', pick: (n) => n.bytes, series: (n) => n.series },
  sent: { label: 'Sent (top senders)', hue: 'var(--flow-remote)', pick: (n) => n.sentBytes, series: (n) => n.sentSeries },
  received: { label: 'Received (top consumers)', hue: 'var(--flow-file)', pick: (n) => n.recvBytes, series: (n) => n.recvSeries },
};

export function createHeatmapView({
  store,
  getModel = () => null,
  onShowInTraffic = () => {},
  onShowInTopology = () => {},
} = {}) {
  const $ = (id) => document.getElementById(id);
  const dom = {};
  for (const id of [
    'h-grid', 'h-empty', 'h-empty-title', 'h-empty-blurb', 'h-empty-clear',
    'h-metric', 'h-rows', 'h-scale', 'h-search', 'h-export-csv',
    'h-legend-min', 'h-legend-max', 'h-legend-bar', 'h-summary',
    'h-drawer', 'h-drawer-body', 'h-drawer-close', 'h-tooltip',
  ]) dom[id] = $(id);

  const view = {
    metric: 'total',
    rows: 20,
    perRowScale: false, // false = one scale across all rows, so rows compare
    query: '',
    graph: { nodes: [], edges: [], unit: 'bytes' },
    selected: null,
    visible: false,
  };

  /* ------------------------------------------------------------------ data */

  function rebuild() {
    const snapshot = store.state.snapshot;
    view.graph = buildFlowGraph({
      snapshot,
      model: getModel(),
      options: { groupInternet: true, query: view.query },
    });
    render();
  }

  /** Rows for the chosen metric, biggest first, with their per-second series. */
  function rankedRows() {
    const metric = METRICS[view.metric];
    // Series are trimmed to the elapsed part of the window, so a short capture
    // fills the strip instead of hiding in its last few columns.
    const shown = visibleBuckets(view.graph);
    return view.graph.nodes
      .map((node) => ({
        node,
        weight: metric.pick(node) || 0,
        series: tailOf(metric.series(node), shown),
      }))
      .filter((row) => row.weight > 0)
      .sort((a, b) => b.weight - a.weight)
      .slice(0, view.rows);
  }

  /* --------------------------------------------------------------- render */

  function render() {
    if (!view.visible) return;
    const rows = rankedRows();
    const unit = view.graph.unit;
    const metric = METRICS[view.metric];
    const window = store.state.snapshot?.window;
    const buckets = visibleBuckets(view.graph);
    const bucketMs = window?.bucketMs || 1000;
    const endsAt = window?.now || Date.now();

    renderEmptyState(rows.length);
    renderSummary(rows, unit);

    // One scale across every row makes rows comparable, which is the point of a
    // ranked view; per-row rescaling instead reveals the shape of a quiet
    // device's activity, which a global scale flattens to nothing.
    const globalMax = Math.max(1, ...rows.flatMap((row) => row.series || [0]));
    dom['h-legend-min'].textContent = '0';
    dom['h-legend-max'].textContent = view.perRowScale
      ? 'each row’s own peak'
      : `${formatWeight(globalMax, unit)}/s`;
    dom['h-legend-bar'].style.background =
      `linear-gradient(90deg, var(--bg-soft) 0%, ${metric.hue} 100%)`;

    const grid = dom['h-grid'];
    grid.replaceChildren();
    if (!rows.length) return;

    grid.append(headerRow(buckets, bucketMs, endsAt));
    for (const row of rows) {
      grid.append(dataRow(row, { unit, metric, globalMax, buckets, bucketMs, endsAt }));
    }
  }

  function headerRow(buckets, bucketMs, endsAt) {
    const head = el('div', { className: 'hm-row hm-head' });
    head.append(el('div', { className: 'hm-label', text: 'device' }));
    head.append(el('div', { className: 'hm-num', text: 'sent' }));
    head.append(el('div', { className: 'hm-num', text: 'recv' }));

    // Only a few ticks: one per second would be unreadable at 90 columns.
    const strip = el('div', { className: 'hm-strip hm-axis' });
    const step = Math.max(1, Math.round(buckets / 6));
    for (let i = 0; i < buckets; i++) {
      const cell = el('div', { className: 'hm-tick' });
      if (i % step === 0 || i === buckets - 1) {
        const secondsAgo = Math.round(((buckets - 1 - i) * bucketMs) / 1000);
        cell.textContent = i === buckets - 1 ? 'now' : `-${secondsAgo}s`;
        cell.classList.add('labelled');
      }
      strip.append(cell);
    }
    head.append(strip);
    return head;
  }

  function dataRow(row, { unit, metric, globalMax, buckets, bucketMs, endsAt }) {
    const { node, series } = row;
    const line = el('div', { className: 'hm-row' });
    if (view.selected === node.id) line.classList.add('selected');

    const label = el('div', { className: 'hm-label' }, [
      el('span', { className: 'hm-icon', text: node.icon || '•' }),
      el('span', { className: 'hm-name', text: node.label }),
    ]);
    label.setAttribute('title', node.ip || node.label);
    line.append(label);

    // The two totals sit beside every row whichever metric is ranking, so a
    // top-senders view still shows what that device pulled down.
    const sent = el('div', { className: `hm-num${view.metric === 'sent' ? ' active' : ''}`, text: formatWeight(node.sentBytes, unit) });
    const recv = el('div', { className: `hm-num${view.metric === 'received' ? ' active' : ''}`, text: formatWeight(node.recvBytes, unit) });
    line.append(sent, recv);

    const rowMax = view.perRowScale
      ? Math.max(1, ...(series || [0]))
      : globalMax;
    const strip = el('div', { className: 'hm-strip' });
    for (let i = 0; i < buckets; i++) {
      const value = series?.[i] || 0;
      const cell = el('div', { className: 'hm-cell' });
      if (value > 0) {
        // Square-root eases the ramp: byte counts are heavy-tailed, and a linear
        // scale leaves everything but the single busiest second looking idle.
        const intensity = Math.min(1, Math.sqrt(value / rowMax));
        cell.style.setProperty('--i', intensity.toFixed(3));
        cell.style.background = metric.hue;
        cell.style.opacity = String(0.1 + intensity * 0.9);
        cell.dataset.value = String(value);
        cell.dataset.at = String(endsAt - (buckets - 1 - i) * bucketMs);
      }
      strip.append(cell);
    }
    strip.addEventListener('pointermove', (event) => showTooltip(event, node, unit, metric));
    strip.addEventListener('pointerleave', hideTooltip);
    line.append(strip);

    line.addEventListener('click', () => {
      view.selected = node.id;
      openDrawer(node);
      render();
    });
    return line;
  }

  function renderSummary(rows, unit) {
    const stats = view.graph.stats;
    dom['h-summary'].replaceChildren();
    if (!stats) return;
    const seconds = Math.max(1, (stats.elapsedMs || 0) / 1000);
    const senders = [...view.graph.nodes].sort((a, b) => b.sentBytes - a.sentBytes)[0];
    const consumers = [...view.graph.nodes].sort((a, b) => b.recvBytes - a.recvBytes)[0];
    const tiles = [
      [formatWeight(stats.bytes, unit), unit === 'bytes' ? 'total' : 'connections'],
      [unit === 'bytes' ? formatRate(stats.bytes / seconds) : formatCount(stats.packets), unit === 'bytes' ? 'average rate' : 'observations'],
      [senders ? truncate(senders.label, 14) : '—', 'top sender'],
      [consumers ? truncate(consumers.label, 14) : '—', 'top consumer'],
    ];
    for (const [value, label] of tiles) {
      dom['h-summary'].append(el('div', { className: 'stat' }, [
        el('b', { text: value }),
        el('span', { text: label }),
      ]));
    }
  }

  function renderEmptyState(shown) {
    const captured = (store.state.snapshot?.endpoints || []).length > 0;
    const filtering = Boolean(view.query.trim());
    const active = store.state.running || store.state.pending;

    dom['h-empty-clear'].hidden = true;
    if (shown > 0) {
      dom['h-empty'].hidden = true;
      return;
    }
    dom['h-empty'].hidden = false;

    if (captured && filtering) {
      dom['h-empty-title'].textContent = 'Nothing matches';
      dom['h-empty-blurb'].textContent = 'The capture has traffic, but no device matches this search.';
      dom['h-empty-clear'].hidden = false;
    } else if (captured) {
      // Ranked rows need a non-zero figure for the chosen direction.
      dom['h-empty-title'].textContent = `Nothing ${view.metric === 'sent' ? 'sent' : view.metric === 'received' ? 'received' : 'recorded'} yet`;
      dom['h-empty-blurb'].textContent = view.metric === 'total'
        ? 'The capture has endpoints but no volume against them yet.'
        : `No device has ${view.metric === 'sent' ? 'sent' : 'received'} anything in this window. Try ranking by total.`;
    } else if (active) {
      dom['h-empty-title'].textContent = 'Listening…';
      dom['h-empty-blurb'].textContent = 'Rows appear as soon as devices start moving traffic.';
    } else if (store.state.everCaptured) {
      dom['h-empty-title'].textContent = 'No traffic seen';
      dom['h-empty-blurb'].textContent =
        'Nothing crossed this capture point during the window. Start a capture from the sidebar.';
    } else {
      dom['h-empty-title'].textContent = 'No traffic captured yet';
      dom['h-empty-blurb'].textContent =
        'Start a capture from the sidebar to see which devices send and receive the most, and when.';
    }
  }

  /* -------------------------------------------------------------- tooltip */

  function showTooltip(event, node, unit, metric) {
    const cell = event.target.closest?.('.hm-cell');
    if (!cell || !cell.dataset.value) return hideTooltip();
    const value = Number(cell.dataset.value);
    const at = Number(cell.dataset.at);
    const tip = dom['h-tooltip'];
    tip.textContent = `${node.label} · ${metric.label.replace(/ \(.*\)$/, '')} `
      + `${formatWeight(value, unit)}${unit === 'bytes' ? '/s' : ` ${weightNoun(unit, value)}`}`
      + ` · ${new Date(at).toLocaleTimeString()}`;
    tip.hidden = false;
    // Kept inside the viewport, so a row at the far right stays readable.
    const width = tip.getBoundingClientRect().width || 240;
    tip.style.left = `${Math.min(event.clientX + 12, window.innerWidth - width - 12)}px`;
    tip.style.top = `${event.clientY + 14}px`;
    return undefined;
  }

  function hideTooltip() {
    dom['h-tooltip'].hidden = true;
  }

  /* --------------------------------------------------------------- drawer */

  function openDrawer(node) {
    const unit = view.graph.unit;
    const body = dom['h-drawer-body'];
    body.replaceChildren();

    body.append(el('div', { className: 'dv-head' }, [
      el('div', { className: 'dv-icon', text: node.icon || '•' }),
      el('div', {}, [
        el('div', { className: 'dv-title', text: node.label }),
        el('div', { className: 'dv-ip mono', text: node.ip || node.sublabel || '' }),
      ]),
    ]));

    const device = node.device;
    body.append(el('div', { className: 'chips' }, [
      device ? chip(CATEGORIES[device.category]?.label || 'device', 'accent') : null,
      node.identifiedVia ? chip(`matched by ${node.identifiedVia === 'mac' ? 'MAC' : node.identifiedVia === 'ip' ? 'IP' : 'name'}`, 'good') : null,
      chip(`${formatCount(node.peerCount)} peer${node.peerCount === 1 ? '' : 's'}`),
    ].filter(Boolean)));

    const peak = peakOf(node.series);
    body.append(section('Volume', kv([
      ['Sent', formatWeight(node.sentBytes, unit)],
      ['Received', formatWeight(node.recvBytes, unit)],
      ['Ratio', ratioLabel(node, unit)],
      ['Busiest second', peak.value > 0 ? `${formatWeight(peak.value, unit)}${unit === 'bytes' ? '/s' : ''}` : '—'],
      ['Packets', unit === 'bytes' ? formatCount(node.packets) : null],
    ])));

    if (node.mac || device) {
      body.append(section('Identity', kv([
        ['MAC', node.mac || 'unknown', true],
        ['Vendor', node.vendor || 'unknown'],
        ['Hostname', device?.hostname || '—'],
      ])));
    }

    if (node.classes?.length) {
      const table = el('table', { className: 'ports' });
      table.append(el('thead', {}, [el('tr', {}, [
        el('th', { text: 'Type' }),
        el('th', { text: unit === 'bytes' ? 'Bytes' : 'Conns' }),
      ])]));
      const tbody = el('tbody');
      for (const entry of node.classes) {
        tbody.append(el('tr', {}, [
          el('td', { text: TRAFFIC_CLASSES[entry.key]?.label || entry.key }),
          el('td', { text: formatWeight(entry.bytes, unit) }),
        ]));
      }
      table.append(tbody);
      body.append(section('Traffic types', table));
    }

    if (node.processes?.length) {
      body.append(section('Processes on this machine',
        el('div', { className: 'chips' }, node.processes.slice(0, 12).map((p) => chip(p)))));
    }

    const links = el('div', { className: 'dv-links' });
    const toTraffic = el('button', { className: 'link', text: 'Show in traffic map →' });
    toTraffic.addEventListener('click', () => onShowInTraffic(node.id));
    links.append(toTraffic);
    if (device) {
      const toTopology = el('button', { className: 'link', text: 'Show in topology →' });
      toTopology.addEventListener('click', () => onShowInTopology(device.ip));
      links.append(toTopology);
    }
    body.append(links);

    dom['h-drawer'].hidden = false;
  }

  function closeDrawer() {
    dom['h-drawer'].hidden = true;
    view.selected = null;
    render();
  }

  function ratioLabel(node, unit) {
    const sent = node.sentBytes;
    const recv = node.recvBytes;
    if (!sent && !recv) return null;
    if (!recv) return 'sends only';
    if (!sent) return 'receives only';
    const ratio = sent / recv;
    if (ratio > 1.2) return `sends ${ratio.toFixed(1)}× what it receives`;
    if (ratio < 0.8) return `receives ${(1 / ratio).toFixed(1)}× what it sends`;
    return 'balanced';
  }

  function peakOf(series) {
    let value = 0;
    let index = -1;
    for (let i = 0; i < (series?.length || 0); i++) {
      if (series[i] > value) {
        value = series[i];
        index = i;
      }
    }
    return { value, index };
  }

  /* ---------------------------------------------------------------- export */

  function exportCsv() {
    const rows = rankedRows();
    const unit = view.graph.unit;
    const window = store.state.snapshot?.window;
    const buckets = visibleBuckets(view.graph);
    const bucketMs = window?.bucketMs || 1000;
    const endsAt = window?.now || Date.now();

    const times = [];
    for (let i = 0; i < buckets; i++) {
      times.push(new Date(endsAt - (buckets - 1 - i) * bucketMs).toISOString());
    }
    const escape = (value) => `"${String(value).replace(/"/g, '""')}"`;
    const lines = [
      `# unit=${unit} metric=${view.metric}`,
      ['device', 'address', 'mac', 'sent', 'received', ...times].map(escape).join(','),
    ];
    for (const row of rows) {
      lines.push([
        row.node.label,
        row.node.ip || '',
        row.node.mac || '',
        row.node.sentBytes,
        row.node.recvBytes,
        ...Array.from({ length: buckets }, (_, i) => row.series?.[i] || 0),
      ].map(escape).join(','));
    }
    download('traffic-heatmap.csv', new Blob([lines.join('\n')], { type: 'text/csv' }));
  }

  /* --------------------------------------------------------------- wire up */

  dom['h-metric'].addEventListener('change', () => {
    view.metric = dom['h-metric'].value;
    render();
  });
  dom['h-rows'].addEventListener('change', () => {
    view.rows = Number(dom['h-rows'].value) || 20;
    render();
  });
  dom['h-scale'].addEventListener('change', () => {
    view.perRowScale = dom['h-scale'].value === 'row';
    render();
  });
  dom['h-export-csv'].addEventListener('click', exportCsv);
  dom['h-drawer-close'].addEventListener('click', closeDrawer);
  dom['h-empty-clear'].addEventListener('click', () => {
    view.query = '';
    dom['h-search'].value = '';
    rebuild();
  });

  let searchTimer = null;
  dom['h-search'].addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      view.query = dom['h-search'].value;
      rebuild();
    }, 160);
  });

  store.subscribe(() => {
    if (view.visible) rebuild();
  });

  return {
    show() {
      view.visible = true;
      if (!store.state.snapshot) store.load().catch(() => {});
      rebuild();
    },
    hide() {
      view.visible = false;
      hideTooltip();
    },
    focusSearch() {
      dom['h-search'].focus();
    },
    closeDrawer,
    fit() { /* the heatmap is a flow layout; nothing to frame */ },
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

function truncate(str, max) {
  const s = String(str ?? '');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
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
