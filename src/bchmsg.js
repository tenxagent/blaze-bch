// BCH signed message (Electron Cash / Paytaca format) verification.
// Signed digest = sha256d(0x18 "Bitcoin Signed Message:\n" || compactSize(len) || utf8(message)).
// Signature = base64(header || r || s); header 31..34 = compressed key, recovery id = header - 31.
// Headers 27..30 (uncompressed keys) are rejected on purpose: Paytaca never makes them (decision (a)).
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { decodeCashaddr, sha256d } from './cashaddr.js';

const MAGIC = Uint8Array.of(0x18, ...new TextEncoder().encode('Bitcoin Signed Message:\n'));

function compactSize(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  if (n <= 0xffffffff) return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >>> 24);
  throw new Error('message too long');
}

export function bchMessageBytes(message) {
  const m = new TextEncoder().encode(message);
  const len = compactSize(m.length);
  const out = new Uint8Array(MAGIC.length + len.length + m.length);
  out.set(MAGIC, 0);
  out.set(len, MAGIC.length);
  out.set(m, MAGIC.length + len.length);
  return out;
}

function decodeSignature(b64) {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) throw new Error('signature: not base64');
  const sig = Uint8Array.from(Buffer.from(b64, 'base64'));
  if (sig.length !== 65) throw new Error(`signature: expected 65 bytes, got ${sig.length}`);
  return sig;
}

export const hash160 = (b) => ripemd160(sha256(b));

// Returns { ok: true } or { ok: false, reason }. Throws only on malformed input (bad address/signature encoding).
export function verifyBchMessage({ address, message, signature }) {
  const target = decodeCashaddr(address);
  const sig = decodeSignature(signature);
  const header = sig[0];
  if (header >= 27 && header <= 30) return { ok: false, reason: 'uncompressed-key-not-supported' };
  if (header < 31 || header > 34) throw new Error(`signature: bad header byte ${header}`);
  const recovered = Uint8Array.of(header - 31, ...sig.subarray(1));
  let pub;
  try {
    pub = secp256k1.recoverPublicKey(recovered, sha256d(bchMessageBytes(message)), { prehash: false });
  } catch {
    return { ok: false, reason: 'recovery-failed' };
  }
  if (pub.length !== 33) throw new Error('internal: expected a compressed public key');
  const h = hash160(pub);
  const match = target.type === 0 && target.hash.length === 20 && target.hash.every((b, i) => b === h[i]);
  return match ? { ok: true } : { ok: false, reason: 'address-mismatch' };
}
