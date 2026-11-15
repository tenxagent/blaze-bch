// Portable byte helpers (Node >= 22 and browsers, no Node-only APIs), strict parsing.
const HEX = /^(?:[0-9a-fA-F]{2})*$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function hexToBytes(h) {
  if (typeof h !== 'string' || !HEX.test(h)) throw new Error('not hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export const bytesToHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

export function base64ToBytes(s) {
  if (typeof s !== 'string' || s === '' || !B64.test(s)) throw new Error('not base64');
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export const bytesToBase64 = (u8) => btoa(Array.from(u8, (b) => String.fromCharCode(b)).join(''));
