// NIP-01 event id + BIP-340 Schnorr verification. One verify path for everything (event checker and test vectors).
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const HEX = /^(?:[0-9a-fA-F]{2})*$/;
const LOWER_HEX = (n) => new RegExp(`^[0-9a-f]{${n}}$`);
const ID_RE = LOWER_HEX(64);
const SIG_RE = LOWER_HEX(128);

const fromHex = (h) => {
  if (typeof h !== 'string' || !HEX.test(h)) throw new Error('not hex');
  return Uint8Array.from(Buffer.from(h, 'hex'));
};
const toHex = (u8) => Buffer.from(u8).toString('hex');

// BIP-340 verify. Returns a boolean and never throws (bad encodings, off-curve keys, out-of-range values => false).
export function verifySchnorr(sigHex, msgHex, pubHex) {
  try {
    const sig = fromHex(sigHex);
    const pub = fromHex(pubHex);
    if (sig.length !== 64 || pub.length !== 32) return false;
    return schnorr.verify(sig, fromHex(msgHex), pub) === true;
  } catch {
    return false;
  }
}

// NIP-01: id = sha256(utf8(JSON.stringify([0, pubkey, created_at, kind, tags, content]))).
export function eventId(ev) {
  const ser = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
  return toHex(sha256(new TextEncoder().encode(ser)));
}

function wellFormed(ev) {
  return ev !== null && typeof ev === 'object'
    && typeof ev.id === 'string' && ID_RE.test(ev.id)
    && typeof ev.pubkey === 'string' && ID_RE.test(ev.pubkey)
    && typeof ev.sig === 'string' && SIG_RE.test(ev.sig)
    && Number.isSafeInteger(ev.created_at) && ev.created_at >= 0
    && Number.isInteger(ev.kind) && ev.kind >= 0 && ev.kind <= 65535
    && typeof ev.content === 'string'
    && Array.isArray(ev.tags) && ev.tags.every((t) => Array.isArray(t) && t.every((x) => typeof x === 'string'));
}

// Returns { ok: true } or { ok: false, reason: 'malformed' | 'bad-id' | 'bad-signature' }.
export function verifyEvent(ev) {
  if (!wellFormed(ev)) return { ok: false, reason: 'malformed' };
  if (eventId(ev) !== ev.id) return { ok: false, reason: 'bad-id' };
  if (!verifySchnorr(ev.sig, ev.id, ev.pubkey)) return { ok: false, reason: 'bad-signature' };
  return { ok: true };
}
