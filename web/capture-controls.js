import { formatWeight, formatCount } from '/shared/flows.js';

/**
 * The capture controls in the sidebar — window, interface, sudo, start/stop,
 * status and progress.
 *
 * These belong to no single view: the traffic map and the heatmap are two
 * readings of one capture and share this block. Rendering them from inside a
 * view meant they only updated while that view happened to be on screen, so a
 * capture running behind the heatmap tab reported itself as idle.
 */
export function createCaptureControls({ store }) {
  const $ = (id) => document.getElementById(id);
  const dom = {};
  for (const id of [
    't-window', 't-sudo', 't-iface', 't-start', 't-status', 't-progress', 't-bar-fill',
  ]) dom[id] = $(id);

  let ticker = null;

  function toggle() {
    if (store.state.pending) return; // a start or stop is already in flight
    if (store.state.running) {
      store.stop();
      return;
    }
    const ifaceRaw = dom['t-iface'].value.trim();
    store.start({
      seconds: Number(dom['t-window'].value),
      sudo: dom['t-sudo'].checked,
      ifaces: ifaceRaw ? ifaceRaw.split(/[\s,]+/).filter(Boolean) : null,
    });
  }

  function render() {
    const { running, pending, status } = store.state;
    const active = running || pending;

    dom['t-status'].textContent = status;
    dom['t-start'].textContent = running ? 'Stop capture' : 'Start capture';
    dom['t-start'].classList.toggle('primary', !running);
    // Usable while a capture runs so it can be stopped, but not mid-request.
    dom['t-start'].disabled = pending;
    dom['t-progress'].hidden = !active;

    if (active) startTicker();
    else stopTicker();
  }

  function startTicker() {
    if (ticker !== null) return;
    ticker = setInterval(renderProgress, 250);
    renderProgress();
  }

  function stopTicker() {
    if (ticker !== null) clearInterval(ticker);
    ticker = null;
    dom['t-bar-fill'].classList.remove('indeterminate');
    dom['t-bar-fill'].style.width = '0%';
  }

  function renderProgress() {
    const total = store.state.captureSeconds;
    const elapsed = store.elapsed();
    // A fixed window has a real end to count towards; "until stopped" does not,
    // so the bar sweeps rather than claiming a progress it cannot know.
    const indeterminate = !total || !store.state.startedAt;
    dom['t-bar-fill'].classList.toggle('indeterminate', indeterminate);
    dom['t-bar-fill'].style.width = indeterminate
      ? '100%'
      : `${Math.min(100, (elapsed / total) * 100).toFixed(1)}%`;
  }

  /** Bytes/packets/conversations so far, for a view's own progress readout. */
  function progressDetail(unit = 'bytes') {
    const totals = store.state.snapshot?.totals;
    const total = store.state.captureSeconds;
    const elapsed = store.elapsed();
    const bits = [];
    if (totals) {
      bits.push(unit === 'bytes'
        ? `${formatWeight(totals.bytes, unit)} · ${formatCount(totals.packets)} packets`
        : `${formatCount(totals.bytes)} connections`);
      bits.push(`${formatCount(totals.flows)} conversation${totals.flows === 1 ? '' : 's'}`);
    }
    if (store.state.startedAt) {
      bits.push(total ? `${clock(elapsed)} of ${clock(total)}` : `${clock(elapsed)} elapsed`);
    }
    return bits.join('   ');
  }

  dom['t-start'].addEventListener('click', toggle);
  store.subscribe(render);
  render();

  return { toggle, render, progressDetail };
}

/** Seconds -> m:ss, for the capture countdown. */
export function clock(seconds) {
  const whole = Math.max(0, Math.round(seconds));
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`;
}
