// Bech32 (BIP-173, original constant 1, not bech32m) + NIP-19 npub, written from the specs.
import { convertBits } from './bits.js';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

const hrpExpand = (hrp) => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];

export function bech32Encode(hrp, words) {
  const mod = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...words, ...checksum].map((v) => CHARSET[v]).join('')}`;
}

export function bech32Decode(str, limit = 90) {
  if (typeof str !== 'string') throw new Error('bech32: not a string');
  if (str.length > limit) throw new Error('bech32: too long');
  for (const ch of str) {
    const c = ch.charCodeAt(0);
    if (c < 33 || c > 126) throw new Error('bech32: character out of range');
  }
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) throw new Error('bech32: mixed case');
  const s = str.toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1) throw new Error('bech32: missing separator or empty HRP');
  if (pos + 7 > s.length) throw new Error('bech32: checksum too short');
  const hrp = s.slice(0, pos);
  const data = [...s.slice(pos + 1)].map((ch) => {
    const v = CHARSET.indexOf(ch);
    if (v < 0) throw new Error(`bech32: invalid data character ${JSON.stringify(ch)}`);
    return v;
  });
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error('bech32: bad checksum');
  return { hrp, words: data.slice(0, -6) };
}

const HEX64 = /^[0-9a-f]{64}$/;

export function npubEncode(hex) {
  if (typeof hex !== 'string' || !HEX64.test(hex)) throw new Error('npub: expected 64 lowercase hex chars');
  return bech32Encode('npub', convertBits([...Buffer.from(hex, 'hex')], 8, 5, true));
}

export function npubDecode(npub) {
  const { hrp, words } = bech32Decode(npub);
  if (hrp !== 'npub') throw new Error(`npub: wrong prefix ${JSON.stringify(hrp)}`);
  const bytes = convertBits(words, 5, 8, false);
  if (bytes.length !== 32) throw new Error('npub: payload must be 32 bytes');
  return Buffer.from(bytes).toString('hex');
}
