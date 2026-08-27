/**
 * MAC address helpers. Split out of oui.js, which needs node:fs to load nmap's
 * vendor table and so cannot be served to the browser — these functions are
 * pure, and the traffic view needs them to match captured MACs against scanned
 * devices on both sides of the wire.
 */

/** `4e:86:5d:3:a2:e` / `4E865D03A20E` -> `4E:86:5D:03:A2:0E`, or null. */
export function normalizeMac(mac) {
  if (!mac) return null;
  const raw = String(mac).trim();
  // `arp` on macOS and `tcpdump -e` on BSD both print unpadded octets.
  if (raw.includes(':') || raw.includes('-')) {
    const parts = raw.split(/[:-]/);
    if (parts.length === 6 && parts.every((p) => /^[0-9a-fA-F]{1,2}$/.test(p))) {
      return parts.map((p) => p.padStart(2, '0').toUpperCase()).join(':');
    }
  }
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':');
}

/**
 * A locally-administered / randomized MAC (bit 1 of the first octet). Modern
 * phones and laptops rotate these per network, so the vendor is unknowable.
 */
export function isRandomizedMac(mac) {
  const norm = normalizeMac(mac);
  if (!norm) return false;
  const first = parseInt(norm.slice(0, 2), 16);
  return (first & 0x02) === 0x02;
}

/**
 * A group (multicast or broadcast) destination MAC — bit 0 of the first octet.
 * Covers `ff:ff:ff:ff:ff:ff`, IPv4 multicast `01:00:5e:…` and IPv6 `33:33:…`.
 * These name a group rather than a device, so they must never be recorded as
 * an endpoint's hardware address.
 */
export function isGroupMac(mac) {
  const norm = normalizeMac(mac);
  if (!norm) return false;
  return (parseInt(norm.slice(0, 2), 16) & 0x01) === 0x01;
}
