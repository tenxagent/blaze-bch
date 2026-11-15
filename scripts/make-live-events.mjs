// Step 1 of the live relay test. A RANDOM throwaway key pair (Nostr + BCH) lives in memory only; this writes two SIGNED events
// to <outdir>: binding.json (a kind 10011 with one bch claim) and revoke.json (the same author 1 s later, no claim = revocation).
// The keys are never written anywhere. Next: leak-gate both files, then scripts/live-relay-test.mjs <outdir>.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256d, encodeCashaddr } from '../src/cashaddr.js';
import { bchMessageBytes, hash160 } from '../src/bchmsg.js';
import { eventId } from '../src/nostr.js';
import { npubEncode } from '../src/bech32.js';
import { verificationText, verifyBinding } from '../src/binding.js';

const out = process.argv[2];
if (!out) throw new Error('usage: make-live-events.mjs <outdir>');
const hex = (u8) => Buffer.from(u8).toString('hex');
const nostrSk = schnorr.utils.randomSecretKey();
const bchSk = secp256k1.utils.randomSecretKey();
const pubkey = hex(schnorr.getPublicKey(nostrSk));
const address = encodeCashaddr('bitcoincash', 0, hash160(secp256k1.getPublicKey(bchSk, true)));
const rec = secp256k1.sign(sha256d(bchMessageBytes(verificationText(npubEncode(pubkey)))), bchSk, { prehash: false, format: 'recovered' });
const proof = Buffer.from(Uint8Array.of(31 + rec[0], ...rec.subarray(1))).toString('base64');
const sign = (ev) => {
  ev.id = eventId(ev);
  ev.sig = hex(schnorr.sign(Buffer.from(ev.id, 'hex'), nostrSk));
  return ev;
};
const now = Math.floor(Date.now() / 1000);
const content = 'blaze-bch live relay test (random throwaway key, never funded)';
const binding = sign({ pubkey, created_at: now, kind: 10011, tags: [['i', `bch:${address}`, proof]], content });
const revoke = sign({ pubkey, created_at: now + 1, kind: 10011, tags: [], content });
if (verifyBinding(binding).verified[0] !== address) throw new Error('self-check failed');
writeFileSync(join(out, 'binding.json'), JSON.stringify(binding, null, 1) + '\n');
writeFileSync(join(out, 'revoke.json'), JSON.stringify(revoke, null, 1) + '\n');
console.log(`wrote binding.json + revoke.json for ${npubEncode(pubkey)} / ${address}`);
