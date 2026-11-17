// BCH Schnorr signature check (2019-05-15 upgrade spec, the scheme OP_CHECKSIG accepts for 65-byte signatures). This is NOT BIP-340
// (which Nostr uses): e = sha256(r || 33-byte compressed P || m) and R must have a Y coordinate with Jacobi symbol 1. Never throws.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const { Point } = secp256k1;
const p = Point.Fp.ORDER;
const n = Point.Fn.ORDER;
const num = (b) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

export function verifyBchSchnorr(sig, msg, pubkey) {
  if (!(sig instanceof Uint8Array) || sig.length !== 64 || !(msg instanceof Uint8Array) || msg.length !== 32) return false;
  let P;
  try {
    P = Point.fromBytes(pubkey);
    P.assertValidity();
  } catch {
    return false;
  }
  if (P.is0()) return false;
  const r = num(sig.subarray(0, 32));
  const s = num(sig.subarray(32));
  if (r >= p || s >= n) return false;
  const e = num(sha256(Uint8Array.of(...sig.subarray(0, 32), ...P.toBytes(true), ...msg))) % n;
  const R = Point.BASE.multiplyUnsafe(s).subtract(P.multiplyUnsafe(e));
  if (R.is0()) return false;
  const { x, y } = R.toAffine();
  return x === r && Point.Fp.pow(y, (p - 1n) / 2n) === 1n;
}
