import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanNetwork } from "./scan/index.js";
import { createTrafficMonitor } from "./traffic/index.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const WEB_DIR = path.join(ROOT, "web");
const DATA_DIR = path.join(ROOT, "data");
const LATEST = path.join(DATA_DIR, "latest.json");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// `src/lib` modules that the browser imports directly, so tree-building logic
// lives in exactly one place.
const SHARED = new Set(["topology.js", "classify.js", "flows.js", "mac.js"]);

export function createServer({ scanOptions = {}, trafficOptions = {} } = {}) {
  const state = {
    model: null,
    scanning: false,
    lastError: null,
    events: [], // replayed to clients that connect mid-scan
    clients: new Set(),
    // Traffic gets its own stream: snapshots arrive every second and are large,
    // so they must not crowd out the scan events a late client replays.
    trafficClients: new Set(),
    trafficSnapshot: null,
    trafficError: null,
  };

  const broadcast = (event) => {
    state.events.push(event);
    if (state.events.length > 500) state.events.shift();
    const frame = `data: ${JSON.stringify(event)}\n\n`;
    for (const res of state.clients) {
      try {
        res.write(frame);
      } catch {
        state.clients.delete(res);
      }
    }
  };

  const broadcastTraffic = (event) => {
    if (event.type === "traffic-snapshot" || event.snapshot) {
      state.trafficSnapshot = event.snapshot || state.trafficSnapshot;
    }
    if (event.type === "traffic-error") state.trafficError = event.message;
    const frame = `data: ${JSON.stringify(event)}\n\n`;
    for (const res of state.trafficClients) {
      try {
        res.write(frame);
      } catch {
        state.trafficClients.delete(res);
      }
    }
  };

  const traffic = createTrafficMonitor({ onEvent: broadcastTraffic });

  async function runScan(options = {}) {
    if (state.scanning)
      return { started: false, reason: "a scan is already running" };
    state.scanning = true;
    state.lastError = null;
    state.events = [];

    const merged = { ...scanOptions, ...options };
    broadcast({ type: "started", at: Date.now(), options: summarize(merged) });

    (async () => {
      try {
        const model = await scanNetwork({ ...merged, onEvent: broadcast });
        state.model = model;
        await fs.mkdir(DATA_DIR, { recursive: true });
        await fs.writeFile(LATEST, JSON.stringify(model, null, 2));
        broadcast({ type: "model", at: Date.now(), meta: model.meta });
      } catch (err) {
        state.lastError = String(err?.stack || err);
        broadcast({
          type: "error",
          at: Date.now(),
          message: String(err?.message || err),
        });
      } finally {
        state.scanning = false;
        broadcast({ type: "idle", at: Date.now() });
      }
    })();

    return { started: true };
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const route = url.pathname;

    try {
      if (route === "/api/health") {
        return json(res, 200, {
          ok: true,
          scanning: state.scanning,
          hasModel: Boolean(state.model),
        });
      }

      if (route === "/api/topology") {
        if (!state.model) {
          const cached = await readCached();
          if (cached) state.model = cached;
        }
        if (!state.model) {
          return json(res, 404, {
            error: "no scan yet",
            scanning: state.scanning,
            lastError: state.lastError,
          });
        }
        return json(res, 200, state.model);
      }

      if (route === "/api/scan" && req.method === "POST") {
        const body = await readJson(req);
        const result = await runScan(cleanOptions(body));
        return json(res, result.started ? 202 : 409, {
          ...result,
          scanning: state.scanning,
        });
      }

      if (route === "/api/traffic") {
        return json(res, 200, {
          running: traffic.running,
          vantage: traffic.vantage,
          warnings: traffic.warnings,
          lastError: state.trafficError,
          snapshot: traffic.running ? traffic.snapshot() : state.trafficSnapshot,
        });
      }

      if (route === "/api/traffic/start" && req.method === "POST") {
        const body = await readJson(req);
        const options = cleanTrafficOptions(body);
        const merged = { ...trafficOptions, ...options };
        merged.filter = combineFilters(trafficOptions.filter, options.filter);
        state.trafficError = null;
        const result = await traffic.start(merged);
        return json(res, result.started ? 202 : 409, {
          ...result,
          running: traffic.running,
          warnings: traffic.warnings,
        });
      }

      if (route === "/api/traffic/stop" && req.method === "POST") {
        const result = traffic.stop({ reason: "stopped from the web UI" });
        return json(res, 200, { ...result, running: traffic.running });
      }

      if (route === "/api/traffic/events") {
        openStream(res, req, state.trafficClients, () => {
          const frames = [];
          if (traffic.vantage) {
            frames.push({
              type: "traffic-started",
              at: Date.now(),
              vantage: traffic.vantage,
              replay: true,
            });
          }
          const snapshot = traffic.running ? traffic.snapshot() : state.trafficSnapshot;
          if (snapshot) {
            frames.push({ type: "traffic-snapshot", at: Date.now(), snapshot, replay: true });
          }
          if (!traffic.running) {
            frames.push({ type: "traffic-idle", at: Date.now() });
          }
          return frames;
        });
        return undefined;
      }

      if (route === "/api/events") {
        openStream(res, req, state.clients, () => {
          const frames = [...state.events];
          if (!state.scanning) frames.push({ type: "idle", at: Date.now() });
          return frames;
        });
        return undefined;
      }

      if (route.startsWith("/shared/")) {
        const name = path.basename(route);
        if (!SHARED.has(name)) return notFound(res);
        return sendFile(res, path.join(ROOT, "src", "lib", name));
      }

      const rel = route === "/" ? "index.html" : route.replace(/^\/+/, "");
      const target = path.join(WEB_DIR, rel);
      if (
        !target.startsWith(WEB_DIR + path.sep) &&
        target !== path.join(WEB_DIR, "index.html")
      ) {
        return notFound(res);
      }
      return sendFile(res, target);
    } catch (err) {
      return json(res, 500, { error: String(err?.message || err) });
    }
  });

  return { server, runScan, traffic, state };
}

async function readCached() {
  try {
    return JSON.parse(await fs.readFile(LATEST, "utf8"));
  } catch {
    return null;
  }
}

/** SSE boilerplate: headers, a replay burst, keep-alive pings, cleanup. */
function openStream(res, req, clients, replay) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(": connected\n\n");
  for (const event of replay() || []) {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  }
  clients.add(res);
  const ping = setInterval(() => {
    try {
      res.write(": ping\n\n");
    } catch {
      /* closed */
    }
  }, 20000);
  req.on("close", () => {
    clearInterval(ping);
    clients.delete(res);
  });
}

/** BPF expressions are ANDed, so a caller filter cannot widen the server's. */
function combineFilters(...filters) {
  const parts = filters.filter(Boolean).map((f) => `(${f})`);
  return parts.length ? parts.join(" and ") : null;
}

function cleanTrafficOptions(body) {
  const out = {};
  if (Number.isFinite(body?.seconds)) {
    out.seconds = Math.max(0, Math.min(3600, Math.floor(body.seconds)));
  }
  if (typeof body?.sudo === "boolean") out.sudo = body.sudo;
  if (Number.isFinite(body?.windowSeconds)) {
    out.windowSeconds = Math.max(10, Math.min(600, Math.floor(body.windowSeconds)));
  }
  if (Array.isArray(body?.ifaces)) {
    const safe = body.ifaces
      .filter((name) => typeof name === "string" && /^[a-zA-Z0-9._-]{1,24}$/.test(name))
      .slice(0, 8);
    if (safe.length) out.ifaces = safe;
  }
  // A BPF expression reaches tcpdump's own parser, never a shell, but it is
  // still user input on a command line: allow only expression characters.
  if (typeof body?.filter === "string" && /^[\w\s.:/()\[\]&|!<>=-]{1,200}$/.test(body.filter)) {
    out.filter = body.filter.trim() || null;
  }
  return out;
}

function cleanOptions(body) {
  const out = {};
  if (
    typeof body?.profile === "string" &&
    ["quick", "normal", "deep"].includes(body.profile)
  )
    out.profile = body.profile;
  if (typeof body?.sudo === "boolean") out.sudo = body.sudo;
  if (typeof body?.traceroute === "boolean") out.traceroute = body.traceroute;
  if (Array.isArray(body?.targets)) {
    const safe = body.targets
      .filter((t) => typeof t === "string" && /^[0-9./,-]+$/.test(t))
      .slice(0, 8);
    if (safe.length) out.targets = safe;
  }
  return out;
}

function summarize(options) {
  return {
    profile: options.profile ?? "normal",
    targets: options.targets ?? "auto",
    sudo: Boolean(options.sudo),
  };
}

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": MIME[".json"],
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function notFound(res) {
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
}

async function sendFile(res, filePath) {
  try {
    const data = await fs.readFile(filePath);
    res.writeHead(200, {
      "Content-Type":
        MIME[path.extname(filePath)] || "application/octet-stream",
      "Content-Length": data.length,
      "Cache-Control": "no-cache",
    });
    res.end(data);
  } catch {
    notFound(res);
  }
}

function readJson(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 64 * 1024) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}
