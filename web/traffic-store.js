/**
 * Single source of capture state for every traffic view.
 *
 * The traffic map and the heatmap show the same capture two ways, so they share
 * one event stream, one set of start/stop controls and one snapshot. Giving each
 * view its own would mean two SSE connections carrying the same hundred-kilobyte
 * frames, and two copies of the capture logic to keep in step.
 *
 * Views subscribe for changes and read `state`; they never write to it.
 */

export function createTrafficStore() {
  const state = {
    snapshot: null,
    snapshotAt: 0,      // window.now of the applied snapshot, to reject stale ones
    vantage: null,
    running: false,
    pending: false,     // a start/stop request is in flight
    paused: false,
    warnings: [],
    startedAt: null,    // wall clock the running capture began
    captureSeconds: 0,  // requested window; 0 means "until stopped"
    everCaptured: false,
    status: 'idle',
  };

  const listeners = new Set();
  const notify = () => {
    for (const fn of [...listeners]) {
      try {
        fn(state);
      } catch (err) {
        // One view failing to render must not stop the others from updating.
        console.error('traffic store listener failed', err);
      }
    }
  };

  /**
   * The initial fetch and the event stream race on every page load, and the
   * fetch losing that race used to blank a live view back to its empty state.
   */
  function applySnapshot(snapshot) {
    const at = snapshot?.window?.now || 0;
    if (!snapshot || at < state.snapshotAt) return false;
    state.snapshot = snapshot;
    state.snapshotAt = at;
    if (snapshot.vantage) state.vantage = snapshot.vantage;
    if (snapshot.vantage?.warnings) state.warnings = snapshot.vantage.warnings;
    if (snapshot.vantage?.startedAt) state.startedAt = snapshot.vantage.startedAt;
    if (Number.isFinite(snapshot.vantage?.seconds)) state.captureSeconds = snapshot.vantage.seconds;
    return true;
  }

  async function load() {
    const res = await fetch('/api/traffic');
    if (!res.ok) return;
    const payload = await res.json();
    if (payload.snapshot) {
      state.running = Boolean(payload.running);
      state.warnings = payload.warnings || state.warnings;
      if (payload.running) state.everCaptured = false;
      applySnapshot(payload.snapshot);
      state.status = state.running ? 'capturing…' : 'capture stopped';
    } else if (!state.snapshot) {
      state.running = Boolean(payload.running);
      state.warnings = payload.warnings || [];
      state.status = state.running ? 'capturing…' : 'idle';
    }
    notify();
  }

  async function start({ seconds, sudo, ifaces }) {
    if (state.pending || state.running) return;
    state.pending = true;
    state.captureSeconds = Number.isFinite(seconds) ? seconds : 0;
    state.startedAt = Date.now(); // provisional until the server reports its own
    state.status = 'starting…';
    notify();

    const payload = { seconds: state.captureSeconds, sudo: Boolean(sudo) };
    if (ifaces?.length) payload.ifaces = ifaces;

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
        if (info.vantage) state.vantage = info.vantage;
        if (info.warnings) state.warnings = info.warnings;
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

    // Cleared before notifying, or the controls would stay disabled.
    state.pending = false;
    if (!started) state.startedAt = null;
    state.status = message;
    notify();
  }

  async function stop() {
    if (state.pending || !state.running) return;
    state.pending = true;
    state.status = 'stopping…';
    notify();
    try {
      await fetch('/api/traffic/stop', { method: 'POST' });
    } catch {
      /* the stopped event, or the next load, will correct the display */
    }
    state.pending = false;
    state.running = false;
    state.everCaptured = true;
    state.startedAt = null;
    state.status = 'capture stopped';
    notify();
  }

  function setPaused(paused) {
    state.paused = paused;
    state.status = paused ? 'paused — the view is frozen' : 'capturing…';
    notify();
  }

  function connect() {
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
          if (data.vantage) state.vantage = data.vantage;
          if (data.vantage?.warnings) state.warnings = data.vantage.warnings;
          // A client connecting mid-capture learns the window from the event,
          // so its progress bar counts towards the same end.
          if (data.vantage?.startedAt) state.startedAt = data.vantage.startedAt;
          if (Number.isFinite(data.seconds)) state.captureSeconds = data.seconds;
          else if (Number.isFinite(data.vantage?.seconds)) state.captureSeconds = data.vantage.seconds;
          state.status = data.message || 'capturing…';
          notify();
          break;

        case 'traffic-phase':
          state.status = data.message || 'capturing…';
          notify();
          break;

        case 'traffic-warning':
          if (data.message && !state.warnings.includes(data.message)) {
            state.warnings = [...state.warnings, data.message];
          }
          notify();
          break;

        case 'traffic-snapshot':
          if (state.paused) break;
          state.running = data.snapshot?.vantage?.running ?? state.running;
          if (applySnapshot(data.snapshot)) {
            state.status = state.running ? 'capturing…' : 'capture stopped';
            notify();
          }
          break;

        case 'traffic-stopped':
          state.running = false;
          state.everCaptured = true;
          state.startedAt = null;
          if (!state.paused) applySnapshot(data.snapshot);
          state.status = data.message || 'capture stopped';
          notify();
          break;

        case 'traffic-idle':
          state.running = false;
          state.startedAt = null;
          state.status = state.snapshot ? 'capture stopped' : 'idle';
          notify();
          break;

        default:
          break;
      }
    });
    source.addEventListener('error', () => { /* EventSource retries on its own */ });
  }

  connect();

  return {
    state,
    load,
    start,
    stop,
    setPaused,
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    /** Seconds elapsed in the running capture, for progress bars. */
    elapsed() {
      return state.startedAt ? (Date.now() - state.startedAt) / 1000 : 0;
    },
  };
}
