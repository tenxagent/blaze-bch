// CashAddr (BCH address format) + legacy base58check, written from the spec:
// https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
import { sha256 } from '@noble/hashes/sha2.js';
import { convertBits } from './bits.js';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
const SIZE_CODE = { 160: 0, 192: 1, 224: 2, 256: 3, 320: 4, 384: 5, 448: 6, 512: 7 };
const SIZE_BITS = Object.fromEntries(Object.entries(SIZE_CODE).map(([b, c]) => [c, Number(b)]));

function polymod(values) {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= GEN[i];
  }
  return c ^ 1n;
}

const prefixValues = (prefix) => [...prefix].map((ch) => ch.charCodeAt(0) & 0x1f);

// Split "prefix:payload", enforce single-case, return lowercase parts and the 5-bit payload values.
function split(addr) {
  if (typeof addr !== 'string') throw new Error('cashaddr: not a string');
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) throw new Error('cashaddr: mixed case');
  const s = addr.toLowerCase();
  const i = s.indexOf(':');
  if (i <= 0) throw new Error('cashaddr: missing prefix');
  const prefix = s.slice(0, i);
  const payload = s.slice(i + 1);
  if (payload.includes(':')) throw new Error('cashaddr: more than one prefix');
  const data = [...payload].map((ch) => {
    const v = CHARSET.indexOf(ch);
    if (v < 0) throw new Error(`cashaddr: invalid character ${JSON.stringify(ch)}`);
    return v;
  });
  return { prefix, data };
}

export function verifyChecksum(addr) {
  try {
    const { prefix, data } = split(addr);
    return polymod([...prefixValues(prefix), 0, ...data]) === 0n;
  } catch {
    return false;
  }
}

export function encodeCashaddr(prefix, type, hash) {
  const code = SIZE_CODE[hash.length * 8];
  if (code === undefined) throw new Error(`cashaddr: unsupported hash size ${hash.length} bytes`);
  if (!Number.isInteger(type) || type < 0 || type > 15) throw new Error('cashaddr: type must be 0-15');
  const payload = convertBits([(type << 3) | code, ...hash], 8, 5, true);
  const mod = polymod([...prefixValues(prefix), 0, ...payload, 0, 0, 0, 0, 0, 0, 0, 0]);
  const checksum = Array.from({ length: 8 }, (_, i) => Number((mod >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:${[...payload, ...checksum].map((v) => CHARSET[v]).join('')}`;
}

export function decodeCashaddr(addr) {
  const { prefix, data } = split(addr);
  if (data.length < 8 || polymod([...prefixValues(prefix), 0, ...data]) !== 0n) {
    throw new Error('cashaddr: bad checksum');
  }
  const bytes = convertBits(data.slice(0, -8), 5, 8, false);
  const version = bytes[0];
  if (version & 0x80) throw new Error('cashaddr: reserved version bit set');
  const bits = SIZE_BITS[version & 7];
  const hash = Uint8Array.from(bytes.slice(1));
  if (hash.length * 8 !== bits) throw new Error('cashaddr: hash length does not match version byte');
  return { prefix, type: (version >> 3) & 0x0f, hash };
}

// ---- legacy base58check (only to read old-style addresses, e.g. test vectors) ----
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const LEGACY = {
  0x00: { prefix: 'bitcoincash', type: 0 },
  0x05: { prefix: 'bitcoincash', type: 1 },
  0x6f: { prefix: 'bchtest', type: 0 },
  0xc4: { prefix: 'bchtest', type: 1 },
};

export const sha256d = (b) => sha256(sha256(b));

function base58Decode(s) {
  let n = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error(`base58: invalid character ${JSON.stringify(ch)}`);
    n = n * 58n + BigInt(v);
  }
  const out = [];
  while (n > 0n) {
    out.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of s) {
    if (ch !== '1') break;
    out.unshift(0);
  }
  return Uint8Array.from(out);
}

export function decodeLegacy(addr) {
  const raw = base58Decode(addr);
  if (raw.length !== 25) throw new Error('legacy: wrong length');
  const body = raw.subarray(0, 21);
  const want = sha256d(body).subarray(0, 4);
  if (!raw.subarray(21).every((b, i) => b === want[i])) throw new Error('legacy: bad checksum');
  const kind = LEGACY[body[0]];
  if (!kind) throw new Error(`legacy: unknown version byte ${body[0]}`);
  return { ...kind, hash: body.slice(1) };
}

export function legacyToCashaddr(addr) {
  const { prefix, type, hash } = decodeLegacy(addr);
  return encodeCashaddr(prefix, type, hash);
}

// NIP-39 claim "platform:identity"; the identity itself contains a colon (bch:bitcoincash:q...),
// so split at the FIRST colon only.
export function parseClaim(value) {
  const i = typeof value === 'string' ? value.indexOf(':') : -1;
  if (i <= 0 || i === value.length - 1) throw new Error('nip39: malformed claim');
  return { platform: value.slice(0, i), identity: value.slice(i + 1) };
}
