import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeChallenge, challengeText, createLoginVerifier, LOGIN_KIND } from '../src/auth.js';
import { NOSTR_SK, BCH_SK, OTHER_SK, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';

const ORIGIN = 'https://demo.example';
const NOW = 1763200000;
const ch = () => makeChallenge({ origin: ORIGIN, now: NOW, ttl: 300 });
const nostrLogin = (c, over = {}) => signEvent(NOSTR_SK, { kind: LOGIN_KIND, created_at: NOW + 5, content: '',
  tags: [['u', c.origin], ['method', 'LOGIN'], ['challenge', c.nonce]], ...over });

test('a challenge is a fresh 128-bit nonce bound to the origin with an expiry; the BCH text names all three', () => {
  const a = ch();
  const b = ch();
  assert.match(a.nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(a.nonce, b.nonce);
  assert.equal(a.origin, ORIGIN);
  assert.equal(a.expires, NOW + 300);
  assert.equal(challengeText(a), `blaze-bch login\norigin: ${ORIGIN}\nnonce: ${a.nonce}\nexpires: ${new Date((NOW + 300) * 1000).toISOString()}`);
});

test('Nostr login: a signed kind 27235 event with origin + nonce logs the pubkey in', () => {
  const v = createLoginVerifier();
  const c = ch();
  assert.deepEqual(v.verifyNostr(nostrLogin(c), c, NOW + 10), { ok: true, pubkey: nostrPubkey(NOSTR_SK) });
});

test('Nostr login refusals: replay, wrong origin, wrong nonce, wrong kind, stale time, expired, forged', () => {
  const v = createLoginVerifier();
  const c = ch();
  const good = nostrLogin(c);
  assert.equal(v.verifyNostr(good, c, NOW + 10).ok, true);
  assert.deepEqual(v.verifyNostr(good, c, NOW + 11), { ok: false, reason: 'replayed' });
  const c2 = ch();
  assert.deepEqual(v.verifyNostr(nostrLogin(c2, { tags: [['u', 'https://evil.example'], ['method', 'LOGIN'], ['challenge', c2.nonce]] }), c2, NOW + 10),
    { ok: false, reason: 'wrong-origin' });
  assert.deepEqual(v.verifyNostr(nostrLogin(c2, { tags: [['u', ORIGIN], ['method', 'LOGIN'], ['challenge', ch().nonce]] }), c2, NOW + 10),
    { ok: false, reason: 'wrong-challenge' });
  assert.deepEqual(v.verifyNostr(nostrLogin(c2, { kind: 1 }), c2, NOW + 10), { ok: false, reason: 'wrong-kind' });
  assert.deepEqual(v.verifyNostr(nostrLogin(c2, { created_at: NOW - 600 }), c2, NOW + 10), { ok: false, reason: 'stale-event' });
  assert.deepEqual(v.verifyNostr(nostrLogin(c2), c2, NOW + 301), { ok: false, reason: 'expired' });
  assert.deepEqual(v.verifyNostr({ ...nostrLogin(c2), sig: '00'.repeat(64) }, c2, NOW + 10), { ok: false, reason: 'bad-signature' });
  assert.equal(v.verifyNostr(nostrLogin(c2), c2, NOW + 10).ok, true, 'refusals do not burn the nonce');
});

test('BCH login: a signed message over the challenge text logs the address in; replay and other origins refused', () => {
  const v = createLoginVerifier();
  const addr = bchAddress(BCH_SK);
  const c = ch();
  assert.deepEqual(v.verifyBch({ address: addr, signature: signBch(BCH_SK, challengeText(c)) }, c, NOW + 10), { ok: true, address: addr });
  assert.deepEqual(v.verifyBch({ address: addr, signature: signBch(BCH_SK, challengeText(c)) }, c, NOW + 11), { ok: false, reason: 'replayed' });
  const c2 = ch();
  const other = { ...c2, origin: 'https://evil.example' };
  assert.deepEqual(v.verifyBch({ address: addr, signature: signBch(BCH_SK, challengeText(other)) }, c2, NOW + 10),
    { ok: false, reason: 'address-mismatch' });
  assert.deepEqual(v.verifyBch({ address: addr, signature: signBch(OTHER_SK, challengeText(c2)) }, c2, NOW + 10),
    { ok: false, reason: 'address-mismatch' });
  assert.deepEqual(v.verifyBch({ address: addr, signature: signBch(BCH_SK, challengeText(c2)) }, c2, NOW + 301), { ok: false, reason: 'expired' });
  assert.deepEqual(v.verifyBch({ address: addr, signature: 'junk!' }, c2, NOW + 10), { ok: false, reason: 'malformed' });
});
