// Signers for the demo's "try it without a wallet" path. Real users sign in their own wallet (BCH) and NIP-07 signer (Nostr);
// these exist so anyone can watch both checks pass with throwaway keys made in memory, which are never stored or sent.
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { encodeCashaddr, sha256d } from './cashaddr.js';
import { bchMessageBytes, hash160 } from './bchmsg.js';
import { eventId } from './nostr.js';
import { bytesToHex, hexToBytes, bytesToBase64 } from './bytes.js';

export const randomSecretKey = () => secp256k1.utils.randomSecretKey();

// P2PKH cashaddr (type 0) of the compressed public key.
export const bchAddressFromSecret = (sk, prefix = 'bitcoincash') => encodeCashaddr(prefix, 0, hash160(secp256k1.getPublicKey(sk, true)));

// Electron Cash / Paytaca "Sign message": base64(31 + recid || r || s) over sha256d(magic || compactSize(len) || text).
export function signBchMessage(sk, message) {
  const rec = secp256k1.sign(sha256d(bchMessageBytes(message)), sk, { prehash: false, format: 'recovered' });
  return bytesToBase64(Uint8Array.of(31 + rec[0], ...rec.subarray(1)));
}

// NIP-01: fills pubkey, id and the BIP-340 signature. Refuses an event that names another pubkey.
export function signNostrEvent(sk, { pubkey, kind, created_at, tags, content }) {
  const own = bytesToHex(schnorr.getPublicKey(sk));
  if (pubkey !== undefined && pubkey !== own) throw new Error('event pubkey is not this key');
  const ev = { pubkey: own, created_at, kind, tags, content };
  ev.id = eventId(ev);
  ev.sig = bytesToHex(schnorr.sign(hexToBytes(ev.id), sk));
  return ev;
}
