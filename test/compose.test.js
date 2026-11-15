import { test } from 'node:test';
import assert from 'node:assert/strict';
import { composeBinding } from '../src/compose.js';
import { verifyBinding, verificationText } from '../src/binding.js';
import { npubEncode } from '../src/bech32.js';
import { eventId } from '../src/nostr.js';
import { NOSTR_SK, BCH_SK, OTHER_SK, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';
import { schnorr } from '@noble/curves/secp256k1.js';

const pk = nostrPubkey(NOSTR_SK);
const npub = npubEncode(pk);
const addr = bchAddress(BCH_SK);
const proof = signBch(BCH_SK, verificationText(npub));
const sign = (ev) => {
  const e = { ...ev, id: eventId(ev) };
  e.sig = Buffer.from(schnorr.sign(Buffer.from(e.id, 'hex'), NOSTR_SK, new Uint8Array(32))).toString('hex');
  return e;
};

test('no current event: a fresh kind 10011 with just the bch claim, ready for the Nostr signer', () => {
  const ev = composeBinding({ pubkey: pk, address: addr, proof, current: null, now: 1763200000 });
  assert.deepEqual(ev, { pubkey: pk, kind: 10011, created_at: 1763200000, tags: [['i', `bch:${addr}`, proof]], content: '' });
  assert.deepEqual(verifyBinding(sign(ev)).verified, [addr]);
});

test('existing claims are KEPT (10011 is replaceable: dropping them would delete the user\'s other identities)', () => {
  const current = signEvent(NOSTR_SK, { tags: [['i', 'github:someone', 'gist'], ['i', 'twitter:someone', '123']], content: 'hi', created_at: 1763100000 });
  const ev = composeBinding({ pubkey: pk, address: addr, proof, current, now: 1763200000 });
  assert.deepEqual(ev.tags, [['i', 'github:someone', 'gist'], ['i', 'twitter:someone', '123'], ['i', `bch:${addr}`, proof]]);
  assert.equal(ev.content, 'hi');
});

test('re-binding the same address replaces its old proof instead of adding a duplicate', () => {
  const current = signEvent(NOSTR_SK, { tags: [['i', `bch:${addr}`, 'old-proof'], ['i', 'github:someone', 'gist']], created_at: 1763100000 });
  const ev = composeBinding({ pubkey: pk, address: addr, proof, current, now: 1763200000 });
  assert.deepEqual(ev.tags, [['i', 'github:someone', 'gist'], ['i', `bch:${addr}`, proof]]);
});

test('created_at always moves forward past the current event, so relays accept the replacement', () => {
  const current = signEvent(NOSTR_SK, { tags: [], created_at: 1763300000 });
  assert.equal(composeBinding({ pubkey: pk, address: addr, proof, current, now: 1763200000 }).created_at, 1763300001);
});

test('refuses a proof that does not bind THIS address to THIS npub (catch mistakes before signing)', () => {
  assert.throws(() => composeBinding({ pubkey: pk, address: addr, proof: signBch(OTHER_SK, verificationText(npub)), current: null, now: 1 }),
    /address-mismatch/);
  assert.throws(() => composeBinding({ pubkey: pk, address: addr.toUpperCase(), proof, current: null, now: 1 }), /lowercase/);
});

test('refuses a "current" event from another author', () => {
  const current = signEvent(OTHER_SK, { tags: [['i', 'github:x', 'y']] });
  assert.throws(() => composeBinding({ pubkey: pk, address: addr, proof, current, now: 1 }), /author/);
});
