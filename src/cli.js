#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanNetwork } from './scan/index.js';
import { captureTraffic } from './traffic/index.js';
import { buildTree, treeToText, countDevices } from './lib/topology.js';
import { buildFlowGraph, flowsToText, endpointsToText, formatWeight, formatRate, formatCount } from './lib/flows.js';
import { createServer } from './server.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA_DIR = path.join(ROOT, 'data');

const C = process.stdout.isTTY
  ? {
      dim: (s) => `\x1b[2m${s}\x1b[0m`,
      bold: (s) => `\x1b[1m${s}\x1b[0m`,
      cyan: (s) => `\x1b[36m${s}\x1b[0m`,
      green: (s) => `\x1b[32m${s}\x1b[0m`,
      yellow: (s) => `\x1b[33m${s}\x1b[0m`,
      red: (s) => `\x1b[31m${s}\x1b[0m`,
    }
  : { dim: (s) => s, bold: (s) => s, cyan: (s) => s, green: (s) => s, yellow: (s) => s, red: (s) => s };

const HELP = `
${C.bold('topology')} — scan the local network and render it as a topology tree

${C.bold('Usage')}
  topology scan    [options]       Run a scan, print the tree, save JSON
  topology traffic [options]       Watch live traffic, print the busiest flows
  topology serve   [options]       Serve the interactive web map
  topology                         Same as: topology serve --scan

${C.bold('Scan options')}
  --target <cidr>      Subnet or host to scan (repeatable). Default: every
                       local IPv4 subnet that is not a tunnel.
  --profile <name>     quick   host discovery only
                       normal  discovery + top 100 ports          (default)
                       deep    discovery + top 500 ports + -sV + OS detection
  --sudo               Run nmap through sudo -n. Enables ARP discovery, SYN
                       scans and OS fingerprinting. Prime it first with
                       'sudo -v', otherwise it falls back automatically.
  --no-traceroute      Skip the uplink trace.
  --trace-target <ip>  Traceroute destination (default 1.1.1.1).
  --max-hosts <n>      Refuse to auto-scan subnets larger than this (default 4096).
  --group <mode>       category | vendor | none  (affects the printed tree)
  --out <file>         Where to write the JSON (default data/latest.json).
  --json               Print the JSON model to stdout instead of the tree.

${C.bold('Traffic options')}
  --seconds <n>        How long to capture (default 20).
  --iface <name>       Interface to capture on (repeatable). Default: every
                       local non-tunnel interface.
  --filter <bpf>       Extra BPF expression, e.g. 'not port 22'.
  --sudo               Run tcpdump through sudo -n. Without it there is no
                       packet capture, only this machine's open connections.
  --limit <n>          Rows of table to print (default 25).
  --rank <metric>      total | sent | received  — which column ranks the
                       top-talkers table (default total). 'sent' gives top
                       senders, 'received' gives top consumers.
  --json               Print the flow snapshot instead of the table.

${C.bold('Serve options')}
  --port <n>           Default 4173.
  --host <addr>        Default 127.0.0.1 (loopback only).
  --scan               Kick off a scan as soon as the server starts.
  --open               Open the map in the default browser.

${C.bold('Notes')}
  Only scan networks you are responsible for. Discovery is ordinary ARP/ICMP
  and TCP traffic, but it is still traffic someone owns. A capture records
  other people's packets as they pass; the same rule applies, more so.
`;

function parseArgs(argv) {
  const out = { _: [], targets: [], ifaces: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => argv[++i];
    switch (arg) {
      case '-h': case '--help': out.help = true; break;
      case '--target': case '-t': out.targets.push(next()); break;
      case '--profile': case '-p': out.profile = next(); break;
      case '--sudo': out.sudo = true; break;
      case '--no-traceroute': out.traceroute = false; break;
      case '--trace-target': out.tracerouteTarget = next(); break;
      case '--max-hosts': out.maxHosts = Number(next()); break;
      case '--group': case '-g': out.group = next(); break;
      case '--out': case '-o': out.out = next(); break;
      case '--json': out.json = true; break;
      case '--seconds': out.seconds = Number(next()); break;
      case '--iface': case '-i': out.ifaces.push(next()); break;
      case '--filter': out.filter = next(); break;
      case '--limit': out.limit = Number(next()); break;
      case '--rank': out.rank = next(); break;
      case '--port': out.port = Number(next()); break;
      case '--host': out.hostAddr = next(); break;
      case '--scan': out.scan = true; break;
      case '--open': out.open = true; break;
      default:
        if (arg.startsWith('-')) {
          console.error(C.red(`Unknown option: ${arg}`));
          process.exit(2);
        }
        out._.push(arg);
    }
  }
  return out;
}

function progressReporter() {
  let lastLine = '';
  const write = (line) => {
    if (!process.stdout.isTTY) {
      if (line !== lastLine) console.log(line);
      lastLine = line;
      return;
    }
    process.stdout.write(`\r\x1b[2K${line}`);
    lastLine = line;
  };
  return (event) => {
    if (event.type === 'phase') {
      if (process.stdout.isTTY && lastLine) process.stdout.write('\n');
      lastLine = '';
      console.log(`${C.cyan('›')} ${event.message}`);
    } else if (event.type === 'progress') {
      const pct = event.percent != null ? `${event.percent.toFixed(0).padStart(3)}%` : '';
      const eta = event.remainingSeconds ? ` · ~${event.remainingSeconds}s left` : '';
      const found = event.found != null ? ` · ${event.found} found` : '';
      write(C.dim(`  ${event.task || event.phase} ${pct}${eta}${found}`));
    } else if (event.type === 'done') {
      if (process.stdout.isTTY && lastLine) process.stdout.write('\n');
      lastLine = '';
      console.log(`${C.green('✓')} ${event.message}`);
    }
  };
}

async function cmdScan(args) {
  const onEvent = progressReporter();
  const model = await scanNetwork({
    targets: args.targets.length ? args.targets : null,
    profile: args.profile || 'normal',
    sudo: Boolean(args.sudo),
    traceroute: args.traceroute !== false,
    tracerouteTarget: args.tracerouteTarget || '1.1.1.1',
    maxHosts: Number.isFinite(args.maxHosts) ? args.maxHosts : 4096,
    onEvent,
  });

  const outPath = args.out ? path.resolve(args.out) : path.join(DATA_DIR, 'latest.json');
  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, JSON.stringify(model, null, 2));

  if (args.json) {
    console.log(JSON.stringify(model, null, 2));
    return model;
  }

  const tree = buildTree(model, { groupBy: args.group || 'category' });
  console.log('');
  console.log(treeToText(tree).join('\n'));
  console.log('');

  const m = model.meta;
  console.log(`${C.bold('Devices')}  ${countDevices(tree)}   ${C.dim(`method=${m.method}${m.nmapVersion ? ` ${m.nmapVersion}` : ''} profile=${m.profile} privileged=${m.privileged} in ${(m.durationMs / 1000).toFixed(1)}s`)}`);
  console.log(`${C.bold('Saved')}    ${outPath}`);
  for (const w of m.warnings) console.log(`${C.yellow('!')} ${w}`);
  console.log(C.dim(`\nRun 'node src/cli.js serve' to explore the map in a browser,`));
  console.log(C.dim(`or 'node src/cli.js traffic' to see which of these devices are talking.`));
  return model;
}

async function cmdTraffic(args) {
  const seconds = Number.isFinite(args.seconds) ? args.seconds : 20;

  const onEvent = (event) => {
    if (event.type === 'traffic-started') {
      console.log(`${C.cyan('›')} ${event.message}`);
      for (const warning of event.vantage?.warnings || []) console.log(`${C.yellow('!')} ${warning}`);
    } else if (event.type === 'traffic-phase' || event.type === 'traffic-warning') {
      console.log(`${C.cyan('›')} ${event.message}`);
    } else if (event.type === 'traffic-snapshot' && process.stdout.isTTY) {
      const totals = event.snapshot?.totals;
      if (!totals) return;
      const unit = event.snapshot.vantage?.unit || 'bytes';
      process.stdout.write(
        `\r\x1b[2K  ${C.dim(`${formatWeight(totals.bytes, unit)} · ${formatCount(totals.packets)} packets · ${totals.flows} flows`)}`,
      );
    }
  };

  const snapshot = await captureTraffic({
    seconds,
    sudo: Boolean(args.sudo),
    ifaces: args.ifaces.length ? args.ifaces : null,
    filter: args.filter || null,
    onEvent,
  });
  if (process.stdout.isTTY) process.stdout.write('\r\x1b[2K');

  if (args.json) {
    console.log(JSON.stringify(snapshot, null, 2));
    return snapshot;
  }

  // The scan model, when there is one, turns bare addresses into device names.
  let model = null;
  try {
    model = JSON.parse(await fs.readFile(path.join(DATA_DIR, 'latest.json'), 'utf8'));
  } catch {
    /* no scan yet; the table falls back to plain IPs */
  }

  const graph = buildFlowGraph({ snapshot, model, options: {} });
  const unit = graph.unit;
  const seenSeconds = Math.max(1, (graph.stats.elapsedMs || 0) / 1000);

  const limit = Number.isFinite(args.limit) ? args.limit : 25;
  const rank = ['total', 'sent', 'received'].includes(args.rank) ? args.rank : 'total';

  console.log('');
  console.log(C.bold(`Top talkers by ${rank}`));
  console.log(endpointsToText(graph, { limit: Math.min(limit, 12), metric: rank }).join('\n'));
  console.log('');
  console.log(C.bold('Conversations'));
  console.log(flowsToText(graph, { limit }).join('\n'));
  console.log('');
  console.log(
    `${C.bold('Total')}    ${formatWeight(graph.stats.bytes, unit)}` +
    `${unit === 'bytes' ? ` (${formatRate(graph.stats.bytes / seenSeconds)} average)` : ' connections'}` +
    `   ${C.dim(`${graph.stats.shownEdges} conversations · ${graph.stats.shownNodes} endpoints · ${seenSeconds.toFixed(0)}s`)}`,
  );
  const vantage = snapshot.vantage || {};
  console.log(`${C.bold('Method')}   ${vantage.method || 'unknown'}   ${C.dim((vantage.interfaces || []).join(', ') || 'no capture interface')}`);
  if (vantage.sees) console.log(`${C.dim(vantage.sees)}`);
  for (const warning of vantage.warnings || []) console.log(`${C.yellow('!')} ${warning}`);
  if (!model) console.log(C.dim("\nRun 'node src/cli.js scan' first to label these addresses with device names."));
  return snapshot;
}

async function cmdServe(args) {
  const port = Number.isFinite(args.port) ? args.port : 4173;
  const hostAddr = args.hostAddr || '127.0.0.1';
  const { server, runScan } = createServer({
    // Excluded so that watching the live map does not show up as traffic on it.
    trafficOptions: { filter: `not port ${port}` },
    scanOptions: {
      targets: args.targets.length ? args.targets : null,
      profile: args.profile || 'normal',
      sudo: Boolean(args.sudo),
      traceroute: args.traceroute !== false,
      tracerouteTarget: args.tracerouteTarget || '1.1.1.1',
      maxHosts: Number.isFinite(args.maxHosts) ? args.maxHosts : 4096,
    },
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, hostAddr, resolve);
  });

  const url = `http://${hostAddr === '0.0.0.0' ? 'localhost' : hostAddr}:${port}`;
  console.log(`${C.green('✓')} Topology map on ${C.bold(url)}`);
  console.log(C.dim('  Press Ctrl+C to stop.'));

  if (args.scan) {
    console.log(C.dim('  Starting initial scan…'));
    await runScan();
  }
  if (args.open) {
    const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    const { run } = await import('./lib/exec.js');
    run(opener, [url], { timeout: 5000 });
  }
}

const args = parseArgs(process.argv.slice(2));
const command = args._[0] || 'serve';

if (args.help) {
  console.log(HELP);
  process.exit(0);
}

try {
  if (command === 'scan') {
    await cmdScan(args);
  } else if (command === 'traffic') {
    await cmdTraffic(args);
  } else if (command === 'serve') {
    if (!args._[0]) args.scan = args.scan ?? true; // bare `topology` scans too
    await cmdServe(args);
  } else {
    console.error(C.red(`Unknown command: ${command}`));
    console.log(HELP);
    process.exit(2);
  }
} catch (err) {
  console.error(C.red(`\nFailed: ${err?.message || err}`));
  if (process.env.DEBUG) console.error(err);
  process.exit(1);
}
