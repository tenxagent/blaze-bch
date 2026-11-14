import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { verifySchnorr, eventId, verifyEvent } from '../src/nostr.js';
import { TEST_SK_LABEL } from './test-key.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/vectors.json', import.meta.url)));
const N = JSON.parse(readFileSync(new URL('./fixtures/nip01-event.json', import.meta.url)));
const hex = (u8) => Buffer.from(u8).toString('hex');

// ---- (c) BIP-340: all 19 official rows through the SAME function verifyEvent uses ----
test('BIP-340: 19 official vectors (9 valid, 10 invalid) give the expected result', () => {
  assert.equal(V.bip340.length, 19);
  assert.equal(V.bip340.filter((r) => r.expect).length, 9);
  for (const r of V.bip340) {
    assert.equal(verifySchnorr(r.signature, r.message, r.public_key), r.expect, `row ${r.index}: ${r.comment}`);
  }
});

test('verifySchnorr never throws on garbage, it returns false', () => {
  for (const args of [['zz', '', 'abc'], [null, null, null], ['00'.repeat(64), '00'.repeat(32), '0'], [{}, [], 1]]) {
    assert.equal(verifySchnorr(...args), false);
  }
});

// ---- (d) NIP-01 event id + signature ----
// PUBLIC throwaway test key derived from a label string (never funded, never posted to a relay).
const SK = sha256(new TextEncoder().encode(TEST_SK_LABEL));
const BASE = N.event;
const signed = () => {
  const id = eventId(BASE);
  return { ...BASE, id, sig: hex(schnorr.sign(Buffer.from(id, 'hex'), SK, new Uint8Array(32))) };
};

test('NIP-01 id matches a second implementation (Python) on escapes, emoji, control chars, U+2028', () => {
  assert.equal(hex(schnorr.getPublicKey(SK)), BASE.pubkey);
  assert.match(BASE.content, /\u2028/);
  assert.equal(eventId(BASE), N.python_id);
});

test('a correctly signed event verifies', () => {
  assert.deepEqual(verifyEvent(signed()), { ok: true });
});

test('changed content after signing => bad-id', () => {
  assert.deepEqual(verifyEvent({ ...signed(), content: 'x' }), { ok: false, reason: 'bad-id' });
});

test('a tag changed AND the id recomputed => bad-signature', () => {
  const ev = { ...signed(), tags: [['i', 'github:attacker', 'gist']] };
  ev.id = eventId(ev);
  assert.deepEqual(verifyEvent(ev), { ok: false, reason: 'bad-signature' });
});

test('malformed fields are rejected before any crypto (uppercase hex, float time, missing tags...)', () => {
  const ev = signed();
  for (const bad of [{ ...ev, id: ev.id.toUpperCase() }, { ...ev, created_at: 1.5 }, { ...ev, tags: undefined },
    { ...ev, pubkey: ev.pubkey.slice(2) }, { ...ev, kind: '10011' }, { ...ev, tags: [['i', 5]] }, null]) {
    assert.deepEqual(verifyEvent(bad), { ok: false, reason: 'malformed' });
  }
});
