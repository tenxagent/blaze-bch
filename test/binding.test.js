import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyBinding, verificationText } from '../src/binding.js';
import { npubEncode } from '../src/bech32.js';
import { NOSTR_SK, BCH_SK, OTHER_SK, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';

const npub = npubEncode(nostrPubkey(NOSTR_SK));
const addr = bchAddress(BCH_SK);
const proof = signBch(BCH_SK, verificationText(npub));
const bindingEvent = (tags) => signEvent(NOSTR_SK, { tags });

test('the text signed by the BCH key is NIP-39\'s own verification text', () => {
  assert.equal(verificationText(npub), `Verifying that I control the following Nostr public key: ${npub}`);
});

test('a two-key binding verifies: Nostr key signs the event, BCH key signs the npub', () => {
  const r = verifyBinding(bindingEvent([['i', `bch:${addr}`, proof]]));
  assert.equal(r.ok, true);
  assert.equal(r.pubkey, nostrPubkey(NOSTR_SK));
  assert.deepEqual(r.verified, [addr]);
  assert.deepEqual(r.rejected, []);
});

test('the two keys are different (spec: no shared key)', () => {
  assert.notEqual(Buffer.from(NOSTR_SK).toString('hex'), Buffer.from(BCH_SK).toString('hex'));
});

test('a proof made for ANOTHER npub is rejected (copying someone else\'s proof fails)', () => {
  const otherNpub = npubEncode(nostrPubkey(OTHER_SK));
  const r = verifyBinding(bindingEvent([['i', `bch:${addr}`, signBch(BCH_SK, verificationText(otherNpub))]]));
  assert.deepEqual(r.verified, []);
  assert.deepEqual(r.rejected, [{ address: addr, reason: 'address-mismatch' }]);
});

test('a proof signed by a key that does not own the address is rejected', () => {
  const r = verifyBinding(bindingEvent([['i', `bch:${addr}`, signBch(OTHER_SK, verificationText(npub))]]));
  assert.deepEqual(r.rejected, [{ address: addr, reason: 'address-mismatch' }]);
});

test('claims must be canonical lowercase (relay #i lookups match exact strings)', () => {
  const r = verifyBinding(bindingEvent([['i', `bch:${addr.toUpperCase()}`, proof]]));
  assert.deepEqual(r.verified, []);
  assert.deepEqual(r.rejected, [{ address: addr.toUpperCase(), reason: 'non-canonical-address' }]);
});

test('garbage proofs and addresses are rejected per claim, never thrown', () => {
  const r = verifyBinding(bindingEvent([['i', 'bch:bitcoincash:qqqq', proof], ['i', `bch:${addr}`, 'not base64!'],
    ['i', `bch:${addr}`]]));
  assert.deepEqual(r.verified, []);
  assert.deepEqual(r.rejected.map((x) => x.reason), ['malformed-claim', 'malformed-claim', 'malformed-claim']);
});

test('non-bch claims are ignored; one good bch claim among them still verifies', () => {
  const r = verifyBinding(bindingEvent([['i', 'github:someone', 'gist'], ['p', 'x'], ['i', `bch:${addr}`, proof]]));
  assert.deepEqual(r.verified, [addr]);
  assert.deepEqual(r.rejected, []);
});

test('an event that fails NIP-01 or is not kind 10011 binds nothing', () => {
  const ev = bindingEvent([['i', `bch:${addr}`, proof]]);
  assert.deepEqual(verifyBinding({ ...ev, created_at: ev.created_at + 1 }), { ok: false, reason: 'bad-id' });
  assert.deepEqual(verifyBinding(signEvent(NOSTR_SK, { kind: 1, tags: [['i', `bch:${addr}`, proof]] })),
    { ok: false, reason: 'wrong-kind' });
});
