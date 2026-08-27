/**
 * Pan/zoom/fit behaviour for an SVG map, shared by the topology tree and the
 * traffic graph. Each view supplies its own content bounds; everything else —
 * drag-vs-click disambiguation, wheel zoom, fitting — is identical.
 */

export function createCanvas({
  svg,
  viewport,
  container,
  getBounds,
  onBackgroundClick = null,
  onNodeDrag = null,
  minZoom = 0.06,
  maxZoom = 2.6,
  fitMax = 1.15,
  pad = 44,
}) {
  const view = { x: 0, y: 0, k: 1 };

  function applyTransform() {
    viewport.setAttribute('transform', `translate(${view.x},${view.y}) scale(${view.k})`);
  }

  let fittedAt = null; // container size at the last fit, to spot a stale frame

  function fitToView() {
    const rect = container.getBoundingClientRect();
    fittedAt = { width: rect.width, height: rect.height };
    const b = getBounds();
    const width = Math.max(1, b.maxX - b.minX);
    const height = Math.max(1, b.maxY - b.minY);
    const k = Math.min((rect.width - pad * 2) / width, (rect.height - pad * 2) / height, fitMax);
    view.k = Math.max(minZoom, k);
    view.x = pad - b.minX * view.k + Math.max(0, (rect.width - pad * 2 - width * view.k) / 2);
    view.y = pad - b.minY * view.k + Math.max(0, (rect.height - pad * 2 - height * view.k) / 2);
    applyTransform();
  }

  function zoomBy(factor, cx, cy) {
    const rect = container.getBoundingClientRect();
    const px = cx ?? rect.width / 2;
    const py = cy ?? rect.height / 2;
    const k = Math.min(maxZoom, Math.max(minZoom, view.k * factor));
    const ratio = k / view.k;
    view.x = px - (px - view.x) * ratio;
    view.y = py - (py - view.y) * ratio;
    view.k = k;
    applyTransform();
  }

  /**
   * Fit only if the frame could be stale — never fitted, or the container was
   * resized since. Called when a hidden view is shown, so flipping between tabs
   * to compare them does not throw away where you had panned to.
   */
  function fitIfNeeded() {
    const rect = container.getBoundingClientRect();
    if (fittedAt && fittedAt.width === rect.width && fittedAt.height === rect.height) return;
    fitToView();
  }

  /** Client coordinates -> content coordinates, for dropping a dragged node. */
  function toContent(clientX, clientY) {
    const rect = container.getBoundingClientRect();
    return {
      x: (clientX - rect.left - view.x) / view.k,
      y: (clientY - rect.top - view.y) / view.k,
    };
  }

  let panning = false;
  let moved = false;
  let startX = 0;
  let startY = 0;
  let originX = 0;
  let originY = 0;
  let dragging = null; // a node being dragged, when the view supports it

  // Deliberately no setPointerCapture: capturing on the SVG root retargets the
  // follow-up `click` to the root, which would swallow every node click.
  svg.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    moved = false;
    startX = event.clientX;
    startY = event.clientY;

    const handle = onNodeDrag?.hitTest?.(event);
    if (handle) {
      dragging = handle;
      onNodeDrag.start?.(handle, toContent(event.clientX, event.clientY));
      return;
    }
    panning = true;
    originX = view.x;
    originY = view.y;
  });

  window.addEventListener('pointermove', (event) => {
    if (!panning && !dragging) return;
    const dx = event.clientX - startX;
    const dy = event.clientY - startY;
    if (!moved && Math.hypot(dx, dy) < 4) return;
    if (!moved) {
      moved = true;
      if (panning) svg.classList.add('dragging');
    }
    if (dragging) {
      onNodeDrag.move?.(dragging, toContent(event.clientX, event.clientY));
      return;
    }
    view.x = originX + dx;
    view.y = originY + dy;
    applyTransform();
  });

  const stop = () => {
    if (!panning && !dragging) return;
    if (dragging) {
      onNodeDrag?.end?.(dragging, moved);
      dragging = null;
    }
    panning = false;
    svg.classList.remove('dragging');
    // Let the click that follows a pan or a node drag fall through as
    // "ignore me", then clear the flag for the next gesture.
    if (moved) setTimeout(() => { moved = false; }, 0);
  };
  window.addEventListener('pointerup', stop);
  window.addEventListener('pointercancel', stop);

  container.addEventListener('wheel', (event) => {
    event.preventDefault();
    const rect = container.getBoundingClientRect();
    if (event.ctrlKey || event.metaKey || Math.abs(event.deltaY) > Math.abs(event.deltaX)) {
      zoomBy(Math.exp(-event.deltaY * 0.0016), event.clientX - rect.left, event.clientY - rect.top);
    } else {
      view.x -= event.deltaX;
      applyTransform();
    }
  }, { passive: false });

  if (onBackgroundClick) {
    svg.addEventListener('click', () => {
      if (moved) return; // end of a pan, not a deselect
      onBackgroundClick();
    });
  }

  return {
    view,
    applyTransform,
    fitToView,
    fitIfNeeded,
    zoomBy,
    toContent,
    wasDrag: () => moved,
  };
}

/**
 * Standalone-SVG export: clones the live map, inlines the page stylesheet and
 * paints a background, so the downloaded file looks like what was on screen.
 */
export function exportSvgFile(svgEl, bounds, { pad = 30, background = '#0b0f14', filename }) {
  const clone = svgEl.cloneNode(true);
  const width = bounds.maxX - bounds.minX + pad * 2;
  const height = bounds.maxY - bounds.minY + pad * 2;

  // The page's font stack lives on <body>, which the standalone file has not.
  clone.setAttribute('style', 'font-family: ui-sans-serif, -apple-system, system-ui, sans-serif');
  clone.setAttribute('width', width);
  clone.setAttribute('height', height);
  clone.setAttribute('viewBox', `${bounds.minX - pad} ${bounds.minY - pad} ${width} ${height}`);
  clone.querySelector('[data-viewport]')?.removeAttribute('transform');

  const ns = 'http://www.w3.org/2000/svg';
  const style = document.createElementNS(ns, 'style');
  style.textContent = [...document.styleSheets]
    .flatMap((sheet) => {
      try {
        return [...sheet.cssRules].map((rule) => rule.cssText);
      } catch {
        return [];
      }
    })
    .join('\n');
  clone.insertBefore(style, clone.firstChild);

  const rect = document.createElementNS(ns, 'rect');
  rect.setAttribute('x', bounds.minX - pad);
  rect.setAttribute('y', bounds.minY - pad);
  rect.setAttribute('width', width);
  rect.setAttribute('height', height);
  rect.setAttribute('fill', background);
  clone.insertBefore(rect, clone.querySelector('[data-viewport]') || clone.children[1]);

  const xml = new XMLSerializer().serializeToString(clone);
  download(filename, new Blob([`<?xml version="1.0"?>\n${xml}`], { type: 'image/svg+xml' }));
}

export function download(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
