import { surveyNetwork } from '../lib/net.js';
import { FlowTable } from '../lib/flows.js';
import { vendorOf } from '../lib/oui.js';
import * as tcpdump from './tcpdump.js';
import { pollConnections, processIndex } from './connections.js';

/**
 * Traffic monitor: picks the best available observation method, feeds packets
 * into a FlowTable, and emits periodic snapshots.
 *
 * Method choice mirrors the scanner's nmap/ping-sweep split:
 *   tcpdump      real packets and real byte counts, needs root
 *   connections  this machine's open sockets, no privileges, no byte counts
 *
 * Whichever runs, `vantage` records what the numbers actually mean so the UI
 * can label them honestly instead of implying it saw the whole network.
 */

const TUNNEL_RE = /^(utun|wg|tun|tap|ipsec|gpd|ppp)/i;

export function createTrafficMonitor({ onEvent = () => {} } = {}) {
  const state = {
    running: false,
    table: null,
    vantage: null,
    captures: [],
    warnings: [],
    stopTimer: null,
    snapshotTimer: null,
    pollTimer: null,
    seenConnections: new Set(),
    processes: new Map(),
    lastSnapshot: null,
    error: null,
  };

  const emit = (type, payload = {}) => onEvent({ type, at: Date.now(), ...payload });

  function snapshot({ seriesFor = 80, maxFlows = 400 } = {}) {
    if (!state.table) return state.lastSnapshot;
    const snap = state.table.snapshot({
      now: Date.now(),
      seriesFor,
      maxFlows,
      vantage: { ...state.vantage, running: state.running, warnings: state.warnings.slice() },
    });
    // The OUI table needs the filesystem, so vendors for MACs seen on the wire
    // are resolved here rather than in the browser-shared flow model. This is
    // what lets a device the scan never found still show up as, say, an
    // Espressif board rather than a bare address.
    snap.macVendors = vendorsFor(snap.endpoints);
    state.lastSnapshot = snap;
    return snap;
  }

  function vendorsFor(endpoints = []) {
    const out = {};
    for (const endpoint of endpoints) {
      for (const mac of endpoint.macs || []) {
        if (mac in out) continue;
        const vendor = vendorOf(mac);
        if (vendor) out[mac] = vendor;
      }
    }
    return out;
  }

  /**
   * @param {object} options
   * @param {number} options.seconds    stop automatically after this long (0 = run until stopped)
   * @param {boolean} options.sudo      allow `sudo -n tcpdump`
   * @param {string[]} options.ifaces   interfaces to capture on (default: every non-tunnel one)
   * @param {string|null} options.filter extra BPF expression
   * @param {number} options.snapshotMs how often to emit a snapshot
   */
  async function start({
    seconds = 30,
    sudo = false,
    ifaces = null,
    filter = null,
    snapshotMs = 1000,
    windowSeconds = null,
    maxFlows = 4000,
  } = {}) {
    if (state.running) return { started: false, reason: 'a capture is already running' };

    state.running = true;
    state.error = null;
    state.warnings = [];
    state.seenConnections = new Set();
    state.processes = new Map();
    state.captures = [];

    const survey = await surveyNetwork({ maxHosts: Number.MAX_SAFE_INTEGER });
    const selfIps = survey.subnets.map((s) => s.address).filter(Boolean);
    const localCidrs = survey.subnets.filter((s) => !s.isTunnel).map((s) => s.cidr);

    // The ring has to cover the window the user asked for, or the start of a
    // two-minute capture is discarded rather than merely scrolled off: a fixed
    // 90 buckets silently threw away the first 30 seconds. A little headroom
    // absorbs the lag between the request and the first packet.
    const requested = Number.isFinite(windowSeconds) && windowSeconds > 0
      ? windowSeconds
      : (seconds > 0 ? seconds + 10 : 300); // "until stopped" needs some bound
    const buckets = Math.max(60, Math.min(600, Math.ceil(requested)));

    state.table = new FlowTable({
      bucketMs: 1000,
      windowBuckets: buckets,
      maxFlows,
      selfIps,
      localCidrs,
    });

    const candidates = ifaces && ifaces.length
      ? ifaces
      : [...new Set(survey.subnets.filter((s) => !s.isTunnel).map((s) => s.name))];
    const usable = candidates.filter((name) => name && !TUNNEL_RE.test(name));
    for (const name of candidates) {
      if (TUNNEL_RE.test(name)) {
        state.warnings.push(`Skipped ${name} — capturing on a tunnel would record someone else's network.`);
      }
    }

    const haveTcpdump = await tcpdump.tcpdumpAvailable();
    const privileged = tcpdump.isPrivileged();
    let useCapture = haveTcpdump && usable.length > 0;

    if (haveTcpdump && !privileged && !sudo) {
      useCapture = false;
      state.warnings.push('Packet capture needs root. Enable sudo to count bytes per device; without it only this machine\'s own connections are visible.');
    } else if (haveTcpdump && !privileged && sudo && !(await tcpdump.sudoAvailable())) {
      useCapture = false;
      state.warnings.push('sudo -n has no cached credentials, so packet capture could not start. Run `sudo -v` in a terminal first, then start the capture again.');
    } else if (!haveTcpdump) {
      state.warnings.push('tcpdump is not installed, so traffic is read from this machine\'s open sockets instead.');
    } else if (!usable.length) {
      state.warnings.push('No capturable interface found.');
    }

    state.vantage = useCapture
      ? {
          method: 'tcpdump',
          unit: 'bytes',
          bytesKnown: true,
          privileged: privileged || sudo,
          interfaces: usable,
          sees: 'This machine\'s own traffic plus every broadcast and multicast frame on the segment. Unicast between two other devices is not visible from here — a switch does not forward it to this port.',
          startedAt: Date.now(),
          seconds,
          windowSeconds: buckets,
        }
      : {
          method: 'connections',
          unit: 'connections',
          bytesKnown: false,
          privileged: false,
          interfaces: [],
          sees: 'Sockets this machine has open. Every conversation shown has this machine at one end, and the sizes are connection counts, not bytes.',
          startedAt: Date.now(),
          seconds,
          windowSeconds: buckets,
        };

    emit('traffic-started', {
      vantage: state.vantage,
      seconds,
      message: useCapture
        ? `Capturing on ${usable.join(', ')}`
        : 'Sampling this machine\'s open connections',
    });

    if (useCapture) {
      for (const iface of usable) {
        const record = { iface, failed: false };
        const handle = tcpdump.capture({
          iface,
          sudo,
          filter,
          onPacket: (packet) => {
            packet.process = attributeProcess(packet);
            state.table.add(packet);
          },
          onError: (message) => {
            record.failed = true;
            if (!state.warnings.includes(message)) state.warnings.push(message);
            emit('traffic-warning', { message, iface });
            // Only give up on capture once every interface has failed. Keying
            // this off "nothing parsed yet" instead meant one dead interface
            // could tear down a working one during the first second.
            if (state.captures.every((c) => c.record.failed)) fallBackToConnections();
          },
          onReady: () => emit('traffic-phase', { message: `Capturing on ${iface}`, iface }),
        });
        handle.record = record;
        state.captures.push(handle);
      }
    }

    // The connection poll runs either way: as the traffic source when there is
    // no capture, and as the only source of process names when there is one.
    await pump({ asSource: !useCapture, sudo });
    state.pollTimer = setInterval(() => {
      pump({ asSource: state.vantage.method === 'connections', sudo }).catch(() => {});
    }, 3000);

    state.snapshotTimer = setInterval(() => {
      emit('traffic-snapshot', { snapshot: snapshot({ seriesFor: 40, maxFlows: 250 }) });
    }, Math.max(250, snapshotMs));

    if (seconds > 0) {
      state.stopTimer = setTimeout(() => stop({ reason: 'the capture window ended' }), seconds * 1000);
    }

    return { started: true, vantage: state.vantage };
  }

  function fallBackToConnections() {
    if (state.vantage?.method !== 'tcpdump') return;
    for (const handle of state.captures) handle.stop();
    state.captures = [];
    state.vantage = {
      ...state.vantage,
      method: 'connections',
      unit: 'connections',
      bytesKnown: false,
      interfaces: [],
      sees: 'Sockets this machine has open. Every conversation shown has this machine at one end, and the sizes are connection counts, not bytes.',
    };
    emit('traffic-phase', { message: 'Falling back to open-connection sampling' });
  }

  function attributeProcess(packet) {
    const { protocol, src, dst, srcPort, dstPort } = packet;
    if (protocol !== 'tcp' && protocol !== 'udp') return null;
    return (
      state.processes.get(`${protocol}:${src}:${srcPort}`) ||
      state.processes.get(`${protocol}:${dst}:${dstPort}`) ||
      null
    );
  }

  /** One connection poll: refresh process attribution, and add flows if we are the source. */
  async function pump({ asSource, sudo }) {
    const result = await pollConnections({ sudo });
    if (!result.ok) {
      if (asSource && result.warning && !state.warnings.includes(result.warning)) {
        state.warnings.push(result.warning);
      }
      return;
    }
    state.processes = processIndex(result.connections);
    if (result.warning && !state.warnings.includes(result.warning)) state.warnings.push(result.warning);
    if (!asSource || !state.table) return;

    const now = Date.now();
    for (const c of result.connections) {
      const key = `${c.protocol}:${c.localIp}:${c.localPort}:${c.remoteIp}:${c.remotePort}`;
      if (state.seenConnections.has(key)) continue;
      state.seenConnections.add(key);
      // Weight 1 per newly-seen connection: with no byte counts available, the
      // unit the whole view is measured in is "connections". vantage.unit says so.
      state.table.add({
        at: now,
        src: c.localIp,
        dst: c.remoteIp,
        srcPort: c.localPort,
        dstPort: c.remotePort,
        protocol: c.protocol,
        bytes: 1,
        process: c.process,
      });
    }
  }

  function stop({ reason = 'stopped' } = {}) {
    if (!state.running) return { stopped: false };
    state.running = false;
    clearTimeout(state.stopTimer);
    clearInterval(state.snapshotTimer);
    clearInterval(state.pollTimer);
    state.stopTimer = state.snapshotTimer = state.pollTimer = null;
    for (const handle of state.captures) handle.stop();

    if (state.vantage) state.vantage.stoppedAt = Date.now();
    const final = snapshot();
    emit('traffic-stopped', {
      reason,
      message: reason.startsWith('the ') ? `Capture ended — ${reason.slice(4)}` : `Capture ${reason}`,
      stats: final?.totals || null,
      captures: state.captures.map((c) => c.stats),
      snapshot: final,
    });
    state.captures = [];
    return { stopped: true, snapshot: final };
  }

  return {
    start,
    stop,
    snapshot,
    get running() {
      return state.running;
    },
    get vantage() {
      return state.vantage;
    },
    get warnings() {
      return state.warnings;
    },
  };
}

/**
 * One-shot capture for the CLI: run for `seconds`, then resolve the snapshot.
 */
export async function captureTraffic(options = {}) {
  const { onEvent = () => {}, seconds = 20 } = options;
  const monitor = createTrafficMonitor({ onEvent });
  const result = await monitor.start({ ...options, seconds: 0 });
  if (!result.started) throw new Error(result.reason);

  await new Promise((resolve) => setTimeout(resolve, Math.max(1, seconds) * 1000));
  const { snapshot } = monitor.stop({ reason: 'the capture window ended' });
  return snapshot;
}
