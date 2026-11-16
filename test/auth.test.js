import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeChallenge, challengeText, createLoginVerifier, refusalText, LOGIN_KIND } from '../src/auth.js';
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

test('every login refusal has a plain-language explanation, distinct per code, with the code kept at the end', () => {
  const codes = ['expired', 'replayed', 'wrong-origin', 'wrong-challenge', 'wrong-kind', 'stale-event', 'malformed', 'bad-id',
    'bad-signature', 'address-mismatch', 'recovery-failed', 'uncompressed-key-not-supported'];
  const texts = codes.map((code) => {
    const t = refusalText(code);
    assert.ok(t.endsWith(` (${code})`), code);
    assert.ok(t.length > code.length + 30, `${code} has a real sentence`);
    return t;
  });
  assert.equal(new Set(texts).size, codes.length);
  assert.equal(refusalText('some-new-code'), 'some-new-code', 'unknown codes pass through unchanged');
});

test('a BCH signature sent again after a login is refused, and the text says each login issues a new challenge', () => {
  const v = createLoginVerifier();
  const addr = bchAddress(BCH_SK);
  const first = ch();
  const sig = signBch(BCH_SK, challengeText(first));
  assert.equal(v.verifyBch({ address: addr, signature: sig }, first, NOW + 10).ok, true);
  const next = ch(); // the page shows a new challenge after every login
  const r = v.verifyBch({ address: addr, signature: sig }, next, NOW + 12);
  assert.deepEqual(r, { ok: false, reason: 'address-mismatch' });
  assert.match(refusalText(r.reason), /new challenge/);
  assert.match(refusalText(r.reason), /text shown above/);
});
