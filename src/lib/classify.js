/**
 * Infer what a discovered host actually *is* from the weak signals a scan
 * gives us: open ports, service banners, MAC vendor, hostname and OS guess.
 * Every rule records why it fired so the UI can explain itself.
 */

export const CATEGORIES = {
  router: { label: 'Router / Gateway', icon: '🌐', order: 0 },
  network: { label: 'Network Gear', icon: '📡', order: 1 },
  server: { label: 'Servers', icon: '🖧', order: 2 },
  nas: { label: 'Storage / NAS', icon: '💾', order: 3 },
  computer: { label: 'Computers', icon: '💻', order: 4 },
  mobile: { label: 'Phones & Tablets', icon: '📱', order: 5 },
  printer: { label: 'Printers', icon: '🖨️', order: 6 },
  media: { label: 'TV & Media', icon: '📺', order: 7 },
  camera: { label: 'Cameras', icon: '📷', order: 8 },
  iot: { label: 'Smart Home / IoT', icon: '💡', order: 9 },
  virtual: { label: 'Virtual Machines', icon: '📦', order: 10 },
  unknown: { label: 'Unidentified', icon: '❔', order: 11 },
};

// [pattern, category, explanation, weight]. Single-purpose vendors (a camera
// maker only makes cameras) are strong evidence; general computer and phone
// makers ship everything, so they score low.
const VENDOR_HINTS = [
  [/synology|qnap|western digital|wd |netapp|drobo|terra/i, 'nas', 'storage vendor', 18],
  [/brother|lexmark|epson|canon|ricoh|kyocera|xerox|zebra tech/i, 'printer', 'printer vendor', 18],
  [/hikvision|dahua|axis communications|reolink|amcrest|wyze|arlo|foscam/i, 'camera', 'camera vendor', 18],
  [/sonos|roku|vizio|bose|denon|yamaha|nvidia.*shield|chromecast/i, 'media', 'media vendor', 18],
  [/espressif|tuya|shelly|sonoff|itead|nest labs|ecobee|signify|philips light|lifx|tp-link.*kasa|wiz/i, 'iot', 'IoT vendor', 16],
  [/vmware|virtualbox|oracle virt|parallels|qemu|kvm|hyper-v|xensource|docker/i, 'virtual', 'hypervisor MAC range', 20],
  [/ubiquiti|mikrotik|aruba|ruckus|juniper|cisco|meraki|netgear|zyxel|d-link|tenda|eero|amplifi/i, 'network', 'network-equipment vendor', 16],
  [/raspberry pi/i, 'computer', 'Raspberry Pi', 14],
  [/sony interactive|nintendo/i, 'media', 'game console vendor', 16],
  [/apple/i, 'computer', 'Apple device', 8],
  [/samsung|xiaomi|huawei|oneplus|oppo|vivo|realme|motorola|google/i, 'mobile', 'phone vendor', 8],
  [/intel|dell|lenovo|hewlett packard|hp inc|asus|micro-star|gigabyte|asrock|framework|microsoft/i, 'computer', 'PC hardware vendor', 8],
];

const HOSTNAME_HINTS = [
  [/router|gateway|gw\b|\bap\d|access-?point|unifi|omada|openwrt|pfsense|opnsense|edgerouter/i, 'network'],
  [/printer|print|mfp|laserjet|officejet|deskjet|ecotank/i, 'printer'],
  [/\bnas\b|synology|diskstation|qnap|truenas|freenas|unraid/i, 'nas'],
  [/iphone|ipad|android|galaxy|pixel|oneplus|phone|tablet/i, 'mobile'],
  [/macbook|imac|mac-?mini|mac-?studio|desktop|laptop|pc\b|workstation|thinkpad|ubuntu|fedora|debian|arch/i, 'computer'],
  [/\btv\b|appletv|firetv|chromecast|roku|shield|sonos|echo|homepod|soundbar|webos|tizen|bravia|aquos|hisense|viera/i, 'media'],
  [/cam\b|camera|doorbell|ipcam|nvr|blink|ring/i, 'camera'],
  [/hue|bulb|plug|switch\d|thermostat|sensor|shelly|tasmota|esp[-_]?\d*|tuya|smart/i, 'iot'],
  [/server|srv|nginx|proxy|db\d|k8s|node\d|docker|host\d|esxi|proxmox/i, 'server'],
];

const PORT_HINTS = [
  [[631, 9100, 515], 'printer', 'IPP/JetDirect/LPD printing port'],
  [[5000, 5001], 'nas', 'DSM web UI port'],
  [[554, 8554, 37777, 34567], 'camera', 'RTSP/DVR port'],
  [[8009, 8008], 'media', 'Chromecast port'],
  [[1400, 1443], 'media', 'Sonos port'],
  [[8060], 'media', 'Roku ECP port'],
  [[7000, 5000, 3689], 'media', 'AirPlay/DAAP port'],
  [[3389], 'computer', 'RDP'],
  [[5900, 5901], 'computer', 'VNC'],
  [[445, 139], 'computer', 'SMB'],
  [[22], 'server', 'SSH'],
  [[80, 443, 8080, 8443], 'server', 'web server'],
  [[3306, 5432, 27017, 6379, 1433], 'server', 'database port'],
  [[53], 'network', 'DNS service'],
  [[161], 'network', 'SNMP'],
  [[23, 992], 'network', 'telnet management'],
];

const OS_HINTS = [
  [/windows/i, 'computer'],
  [/mac ?os|apple/i, 'computer'],
  [/ios\b|android/i, 'mobile'],
  [/linux|unix|bsd/i, 'server'],
  [/embedded|vxworks|router|switch|firewall|ios \d/i, 'network'],
  [/printer/i, 'printer'],
];

/** Named services worth surfacing as chips in the UI. */
const NOTABLE_PORTS = {
  22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 111: 'RPC',
  139: 'SMB', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  515: 'LPD', 548: 'AFP', 554: 'RTSP', 631: 'IPP', 993: 'IMAPS', 1400: 'Sonos',
  1883: 'MQTT', 2049: 'NFS', 3000: 'HTTP-alt', 3306: 'MySQL', 3389: 'RDP',
  5000: 'UPnP/DSM', 5432: 'Postgres', 5900: 'VNC', 6379: 'Redis', 7000: 'AirPlay',
  8006: 'Proxmox', 8009: 'Cast', 8060: 'Roku', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
  9100: 'JetDirect', 27017: 'MongoDB', 32400: 'Plex', 51820: 'WireGuard',
};

export function serviceName(port, nmapName) {
  return NOTABLE_PORTS[port] || (nmapName && nmapName !== 'unknown' ? nmapName : `tcp/${port}`);
}

/**
 * @param {object} host  { ip, mac, vendor, hostname, os, ports: [{port, service, product}] }
 * @param {object} ctx   { isGateway, isSelf, gatewayIps }
 */
export function classify(host, ctx = {}) {
  const reasons = [];
  const scores = new Map();
  const bump = (cat, weight, why) => {
    if (!cat || !CATEGORIES[cat]) return;
    scores.set(cat, (scores.get(cat) || 0) + weight);
    reasons.push({ cat, weight, why });
  };

  if (ctx.isGateway) bump('router', 100, 'is the default gateway for this network');
  if (ctx.isSelf) bump('computer', 90, 'this machine');

  const vendor = host.vendor || '';
  for (const [re, cat, why, weight] of VENDOR_HINTS) {
    if (re.test(vendor)) { bump(cat, weight, `${why}: ${vendor}`); break; }
  }

  const name = host.hostname || '';
  for (const [re, cat] of HOSTNAME_HINTS) {
    if (re.test(name)) { bump(cat, 18, `hostname looks like a ${CATEGORIES[cat].label.toLowerCase()}: ${name}`); break; }
  }

  const openPorts = (host.ports || []).map((p) => p.port);
  for (const [ports, cat, why] of PORT_HINTS) {
    const hit = ports.find((p) => openPorts.includes(p));
    if (hit !== undefined) bump(cat, cat === 'server' ? 5 : 10, `${why} open (${hit})`);
  }

  const osText = [host.os, ...(host.ports || []).map((p) => `${p.product || ''} ${p.extra || ''}`)].join(' ');
  for (const [re, cat] of OS_HINTS) {
    if (re.test(osText)) { bump(cat, 8, `OS/service fingerprint suggests ${CATEGORIES[cat].label.toLowerCase()}`); break; }
  }

  // "No open ports" is only evidence if we actually looked. In the quick
  // profile nothing was probed, so these rules must stay silent.
  if (ctx.portsKnown && openPorts.length === 0) {
    if (/apple|samsung|google|xiaomi|huawei/i.test(vendor)) {
      bump('mobile', 6, 'consumer vendor with no open ports — likely a phone or tablet');
    } else if (/randomized/i.test(vendor)) {
      bump('mobile', 4, 'randomized MAC and no open ports — typical of a modern phone or laptop');
    }
  }

  let category = 'unknown';
  let best = 0;
  for (const [cat, score] of scores) {
    if (score > best) { best = score; category = cat; }
  }

  const confidence = best >= 90 ? 'high' : best >= 16 ? 'medium' : best > 0 ? 'low' : 'none';

  return {
    category,
    confidence,
    reasons: reasons
      .filter((r) => r.cat === category)
      .sort((a, b) => b.weight - a.weight)
      .map((r) => r.why),
  };
}
