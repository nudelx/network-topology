import { surveyNetwork, parseCidr } from '../lib/net.js';
import { arpTable } from '../lib/arp.js';
import { vendorOf, normalizeMac, ouiSource } from '../lib/oui.js';
import { classify, serviceName } from '../lib/classify.js';
import { resolveNames } from '../lib/names.js';
import { traceroute } from '../lib/traceroute.js';
import { buildTree } from '../lib/topology.js';
import * as nmap from './nmap.js';
import { sweep } from './pingsweep.js';

/**
 * Runs a full topology scan and returns the model the web UI renders.
 *
 * Pipeline: survey local interfaces -> discover hosts -> probe ports ->
 * enrich (ARP, vendor, classification) -> traceroute uplink -> build tree.
 */
export async function scanNetwork({
  targets = null,
  profile = 'normal',
  sudo = false,
  traceroute: doTraceroute = true,
  tracerouteTarget = '1.1.1.1',
  resolveHostnames = true,
  maxHosts = 4096,
  onEvent = () => {},
} = {}) {
  const startedAt = Date.now();
  const warnings = [];
  const emit = (type, payload = {}) => onEvent({ type, at: Date.now(), ...payload });

  emit('phase', { phase: 'survey', message: 'Inspecting local interfaces and routes' });
  const survey = await surveyNetwork({ maxHosts });

  for (const s of survey.subnets) {
    if (s.isTunnel) warnings.push(`Skipped ${s.name} (${s.cidr}) — looks like a VPN/tunnel interface.`);
    else if (s.tooLarge) warnings.push(`Skipped ${s.name} (${s.cidr}) — ${s.size} addresses exceeds the ${maxHosts} host limit.`);
  }

  const scanTargets = targets && targets.length
    ? targets
    : survey.subnets.filter((s) => s.scannable).map((s) => s.cidr);

  if (scanTargets.length === 0) {
    warnings.push('No scannable IPv4 subnet found. Pass an explicit target, e.g. --target 192.168.1.0/24');
  }

  const selfIps = new Set(survey.subnets.map((s) => s.address));
  const gatewayIps = new Set(survey.subnets.map((s) => s.gateway).filter(Boolean));

  emit('phase', {
    phase: 'discover',
    message: `Discovering hosts on ${scanTargets.join(', ') || '(nothing)'}`,
    targets: scanTargets,
  });

  const haveNmap = await nmap.nmapAvailable();

  // `sudo -n` fails outright when no credentials are cached, which would fail
  // every nmap call. Check once and degrade to an unprivileged scan instead.
  let useSudo = Boolean(sudo);
  if (useSudo && !nmap.isPrivileged() && !(await nmap.sudoAvailable())) {
    useSudo = false;
    warnings.push('sudo -n has no cached credentials, so the scan ran unprivileged. Run `sudo -v` in a terminal first, then scan again.');
  }
  const privileged = nmap.isPrivileged() || useSudo;
  const method = haveNmap ? 'nmap' : 'ping-sweep';
  const hostMap = new Map();
  let nmapVersion = null;

  if (haveNmap && scanTargets.length) {
    nmapVersion = await nmap.nmapVersion();
    if (!privileged) {
      warnings.push('Running nmap without root: ARP host discovery, SYN scans and OS detection are unavailable. Re-run with --sudo for a fuller map.');
    }

    const discovery = await nmap.discover(scanTargets, {
      sudo: useSudo,
      onProgress: (p) => emit('progress', { phase: 'discover', ...p }),
    });
    if (discovery.error) warnings.push(`nmap discovery: ${discovery.error}`);
    for (const h of discovery.hosts) hostMap.set(h.ip, h);

    emit('phase', {
      phase: 'discover-done',
      message: `${hostMap.size} host${hostMap.size === 1 ? '' : 's'} responded`,
      count: hostMap.size,
    });

    if (profile !== 'quick' && hostMap.size) {
      emit('phase', { phase: 'probe', message: `Probing ports/services on ${hostMap.size} hosts (${profile})` });
      const probed = await nmap.probe([...hostMap.keys()], {
        profile,
        sudo: useSudo,
        onProgress: (p) => emit('progress', { phase: 'probe', ...p }),
      });
      if (probed.error) warnings.push(`nmap probe: ${probed.error}`);
      for (const h of probed.hosts) {
        const base = hostMap.get(h.ip) || h;
        hostMap.set(h.ip, {
          ...base,
          ports: h.ports.length ? h.ports : base.ports,
          os: h.os || base.os,
          osAccuracy: h.osAccuracy ?? base.osAccuracy,
          osMatches: h.osMatches?.length ? h.osMatches : base.osMatches,
          mac: base.mac || h.mac,
          vendor: base.vendor || h.vendor,
          hops: base.hops ?? h.hops,
          rttMs: base.rttMs ?? h.rttMs,
          uptimeSeconds: h.uptimeSeconds ?? base.uptimeSeconds,
        });
      }

      const openTotal = [...hostMap.values()].reduce((n, h) => n + (h.ports?.length || 0), 0);
      if (openTotal === 0) {
        warnings.push('The port probe found nothing open. Unprivileged connect scans are slow over wireless and hosts can run out their time budget — try --sudo for a SYN scan, or the quick profile if the device list is all you need.');
      }
    }
  } else if (scanTargets.length) {
    if (!haveNmap) warnings.push('nmap not found on PATH — using the built-in ping sweep. Installing nmap adds ARP discovery, service versions, OS detection and a much larger MAC vendor database.');
    const result = await sweep(scanTargets, {
      probePorts: profile !== 'quick',
      resolveNames: false, // handled centrally below, across all methods
      onProgress: (p) => emit('progress', { phase: 'discover', ...p }),
    });
    for (const h of result.hosts) hostMap.set(h.ip, h);
    emit('phase', { phase: 'discover-done', message: `${hostMap.size} hosts responded`, count: hostMap.size });
  }

  // The ARP cache fills in MACs nmap could not see (and thus vendors) when
  // running unprivileged, and can reveal hosts that ignored every probe.
  emit('phase', { phase: 'enrich', message: 'Reading ARP cache and resolving vendors' });
  const arp = await arpTable();
  for (const [ip, entry] of arp) {
    const inScope = scanTargets.some((t) => parseCidr(t)?.contains(ip));
    if (!inScope) continue;
    const existing = hostMap.get(ip);
    if (existing) {
      if (!existing.mac) existing.mac = entry.mac;
    } else {
      hostMap.set(ip, {
        ip, mac: entry.mac, ports: [], hostnames: [], hostname: null,
        reason: 'arp-cache', rttMs: null, hops: 1,
      });
    }
  }

  // Make sure this machine and every gateway appear even if they filtered probes.
  for (const s of survey.subnets) {
    if (!s.scannable) continue;
    for (const ip of [s.address, s.gateway]) {
      if (!ip || hostMap.has(ip)) continue;
      hostMap.set(ip, {
        ip, mac: ip === s.address ? s.mac : arp.get(ip)?.mac || null,
        ports: [], hostnames: [], hostname: ip === s.address ? survey.hostname : null,
        reason: ip === s.address ? 'local-interface' : 'default-route', rttMs: null, hops: ip === s.address ? 0 : 1,
      });
    }
  }

  // Names: most consumer gear is only discoverable over mDNS or NetBIOS.
  if (resolveHostnames && hostMap.size) {
    emit('phase', { phase: 'names', message: `Resolving names for ${hostMap.size} hosts (mDNS, NetBIOS, DNS)` });
    const names = await resolveNames([...hostMap.keys()], {
      onProgress: (p) => emit('progress', { phase: 'names', ...p }),
    });
    let named = 0;
    for (const [ip, entry] of names) {
      const host = hostMap.get(ip);
      if (!host) continue;
      if (!host.hostname) {
        host.hostname = entry.name;
        host.nameSource = entry.source;
        named++;
      }
      host.hostnames = [...new Set([...(host.hostnames || []), entry.name])];
    }
    emit('phase', { phase: 'names-done', message: `Named ${named} additional host${named === 1 ? '' : 's'}` });
  }

  const portsKnown = profile !== 'quick';
  const devices = [...hostMap.values()].map((h) => {
    const mac = normalizeMac(h.mac);
    const vendor = h.vendor || vendorOf(mac);
    const subnet = survey.subnets.find((s) => parseCidr(s.cidr)?.contains(h.ip));
    const isSelf = selfIps.has(h.ip);
    const isGateway = gatewayIps.has(h.ip);
    const ports = (h.ports || []).map((p) => ({
      ...p,
      label: serviceName(p.port, p.service),
    }));

    const enriched = { ...h, mac, vendor, hostname: h.hostname || null, ports };
    const verdict = classify(enriched, { isGateway, isSelf, portsKnown });

    return {
      id: h.ip,
      ip: h.ip,
      mac,
      vendor: vendor || null,
      hostname: enriched.hostname,
      hostnames: h.hostnames || [],
      nameSource: h.nameSource || (h.hostname ? 'DNS' : null),
      os: h.os || null,
      osAccuracy: h.osAccuracy ?? null,
      osMatches: h.osMatches || [],
      ports,
      services: ports.map((p) => p.label),
      rttMs: h.rttMs ?? null,
      hops: h.hops ?? null,
      uptimeSeconds: h.uptimeSeconds ?? null,
      discoveredBy: h.reason || null,
      subnet: subnet?.cidr || null,
      iface: subnet?.name || null,
      isSelf,
      isGateway,
      category: verdict.category,
      confidence: verdict.confidence,
      reasons: verdict.reasons,
    };
  }).sort((a, b) => ipKey(a.ip) - ipKey(b.ip));

  let uplink = null;
  if (doTraceroute) {
    emit('phase', { phase: 'traceroute', message: `Tracing the route to ${tracerouteTarget}` });
    uplink = await traceroute(tracerouteTarget);
    if (uplink.unavailable) warnings.push('traceroute not available — the uplink path is omitted.');
  }

  const model = {
    meta: {
      scannedAt: new Date(startedAt).toISOString(),
      durationMs: Date.now() - startedAt,
      method,
      nmapVersion,
      privileged,
      profile,
      targets: scanTargets,
      host: { hostname: survey.hostname, platform: survey.platform },
      oui: ouiSource(),
      deviceCount: devices.length,
      warnings,
    },
    subnets: survey.subnets,
    devices,
    uplink,
  };

  model.tree = buildTree(model, { groupBy: 'category' });
  emit('done', { message: `Scan complete: ${devices.length} devices in ${((Date.now() - startedAt) / 1000).toFixed(1)}s` });
  return model;
}

function ipKey(ip) {
  return String(ip).split('.').reduce((n, p) => n * 256 + Number(p), 0);
}
