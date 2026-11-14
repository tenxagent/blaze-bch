// Test-only signers. Keys come from PUBLIC labels (test-key.js): never funded, never used for a relay post.
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha256d, encodeCashaddr } from '../src/cashaddr.js';
import { bchMessageBytes, hash160 } from '../src/bchmsg.js';
import { eventId } from '../src/nostr.js';
import { TEST_SK_LABEL } from './test-key.js';

export const keyFrom = (suffix) => sha256(new TextEncoder().encode(`${TEST_SK_LABEL}${suffix}`));
export const NOSTR_SK = keyFrom('');
export const BCH_SK = keyFrom(' / bch');
export const OTHER_SK = keyFrom(' / other');
export const hex = (u8) => Buffer.from(u8).toString('hex');

export const nostrPubkey = (sk) => hex(schnorr.getPublicKey(sk));
export const bchAddress = (sk, prefix = 'bitcoincash') =>
  encodeCashaddr(prefix, 0, hash160(secp256k1.getPublicKey(sk, true)));

// Electron Cash / Paytaca style: base64(31 + recid || r || s) over sha256d(magic || len || text).
export function signBch(sk, text) {
  const rec = secp256k1.sign(sha256d(bchMessageBytes(text)), sk, { prehash: false, format: 'recovered' });
  return Buffer.from(Uint8Array.of(31 + rec[0], ...rec.subarray(1))).toString('base64');
}

export function signEvent(sk, { kind = 10011, tags = [], content = '', created_at = 1763128800 } = {}) {
  const ev = { pubkey: nostrPubkey(sk), created_at, kind, tags, content };
  ev.id = eventId(ev);
  ev.sig = hex(schnorr.sign(Buffer.from(ev.id, 'hex'), sk, new Uint8Array(32)));
  return ev;
}
