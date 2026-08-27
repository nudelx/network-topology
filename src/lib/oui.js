import fs from 'node:fs';
import { normalizeMac, isRandomizedMac } from './mac.js';

/**
 * MAC -> vendor lookup. Prefers nmap's `nmap-mac-prefixes` (~50k entries) when
 * nmap is installed; otherwise falls back to a small built-in table so the
 * output is still useful on a machine without nmap.
 */

const CANDIDATE_PATHS = [
  '/opt/homebrew/share/nmap/nmap-mac-prefixes',
  '/usr/local/share/nmap/nmap-mac-prefixes',
  '/usr/share/nmap/nmap-mac-prefixes',
  '/opt/local/share/nmap/nmap-mac-prefixes',
  'C:\\Program Files (x86)\\Nmap\\nmap-mac-prefixes',
  'C:\\Program Files\\Nmap\\nmap-mac-prefixes',
];

const BUILTIN = {
  '000C29': 'VMware', '005056': 'VMware', '080027': 'Oracle VirtualBox',
  '001C42': 'Parallels', '525400': 'QEMU/KVM', '00155D': 'Microsoft Hyper-V',
  'B827EB': 'Raspberry Pi Foundation', 'DCA632': 'Raspberry Pi Trading',
  'E45F01': 'Raspberry Pi Trading', '2CCF67': 'Raspberry Pi Trading',
  'ACDE48': 'Private', '001A11': 'Google', '3C5AB4': 'Google',
  'F4F5D8': 'Google', 'DA A1 19': 'Google',
  '001B63': 'Apple', '003EE1': 'Apple', 'F0189E': 'Apple', 'A45E60': 'Apple',
  '3C0754': 'Apple', '8C8590': 'Apple', 'D0817A': 'Apple',
  'E4388 3': 'Cisco', '00000C': 'Cisco', '001A2B': 'Cisco',
  'B0BE76': 'TP-Link', '5C899A': 'TP-Link', 'E894F6': 'TP-Link',
  '001374': 'Netgear', '20E52A': 'Netgear', 'A00460': 'Netgear',
  '0018E7': 'Ubiquiti', '245A4C': 'Ubiquiti', '788A20': 'Ubiquiti',
  'FCECDA': 'Ubiquiti', '74ACB9': 'Ubiquiti',
  '001132': 'Synology', '0011D8': 'ASUS', '2CFDA1': 'ASUS',
  '00095B': 'Netgear', '000F B5': 'Netgear',
  '0080 77': 'Brother', '008077': 'Brother', '0000AA': 'Xerox',
  '3C2AF4': 'Brother', '002673': 'Hewlett Packard', '3464A9': 'Hewlett Packard',
  '001E8F': 'Canon', '00BB C1': 'Canon', 'F48E38': 'Amazon Technologies',
  '44650D': 'Amazon Technologies', '68544 D': 'Amazon Technologies',
  '18B430': 'Nest Labs', '641666': 'Sonos', '5CAAFD': 'Sonos',
  'D052A8': 'Roku', 'B0A737': 'Roku', 'AC6 3BE': 'Amazon Technologies',
  '000E58': 'Sonos', '8CFCA0': 'Samsung', '002454': 'Samsung',
  '5CF938': 'Samsung', '001DBA': 'Sony', 'FCF152': 'Sony',
  '001478': 'Xiaomi', '286C07': 'Xiaomi', '28E31F': 'Xiaomi',
  '0024D7': 'Intel', '3C970E': 'Intel', 'A0A8CD': 'Intel',
  '001B21': 'Intel', 'D8FC93': 'Intel',
  'DCA904': 'Espressif (ESP32/IoT)', '246F28': 'Espressif (ESP32/IoT)',
  '84F3EB': 'Espressif (ESP32/IoT)', '7C9EBD': 'Espressif (ESP32/IoT)',
  'ECFABC': 'Espressif (ESP32/IoT)', '3C6105': 'Espressif (ESP32/IoT)',
  '000255': 'IBM', '0050C2': 'IEEE Registration Authority',
};

let table = null;
let source = 'builtin';

function loadTable() {
  if (table) return table;
  table = new Map();

  for (const p of CANDIDATE_PATHS) {
    try {
      if (!fs.existsSync(p)) continue;
      const text = fs.readFileSync(p, 'utf8');
      for (const line of text.split('\n')) {
        if (!line || line[0] === '#') continue;
        const tab = line.indexOf('\t');
        const sep = tab === -1 ? line.indexOf(' ') : tab;
        if (sep === -1) continue;
        const prefix = line.slice(0, sep).trim().toUpperCase();
        const vendor = line.slice(sep + 1).trim();
        if (prefix.length === 6 && vendor) table.set(prefix, vendor);
      }
      if (table.size > 0) {
        source = p;
        return table;
      }
    } catch {
      // Unreadable candidate — try the next one.
    }
  }

  for (const [k, v] of Object.entries(BUILTIN)) {
    table.set(k.replace(/\s+/g, '').toUpperCase(), v);
  }
  return table;
}

export function vendorOf(mac) {
  const norm = normalizeMac(mac);
  if (!norm) return null;
  if (isRandomizedMac(norm)) return 'Randomized MAC (private address)';
  const prefix = norm.replace(/:/g, '').slice(0, 6);
  return loadTable().get(prefix) ?? null;
}

export function ouiSource() {
  loadTable();
  return { source, entries: table.size };
}

// Re-exported so callers that only need MAC formatting can keep importing from
// here; the implementations live in mac.js, which the browser can also load.
export { normalizeMac, isRandomizedMac } from './mac.js';
