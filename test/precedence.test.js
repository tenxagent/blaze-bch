// How an address's on-chain commitment combines with its off-chain (kind 10011) claims.
// The off-chain check still has to pass: the Nostr key must claim the address. The chain adds the BCH key's own, globally ordered say:
// bound to P ⇒ only P may claim the address; revoked ⇒ nobody may; none ⇒ the off-chain answer stands; unknown ⇒ it stands but is not sure.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyOnchain } from '../src/commit.js';

const P = { pubkey: 'a'.repeat(64), npub: 'npub1p' };
const Q = { pubkey: 'b'.repeat(64), npub: 'npub1q' };

test('no on-chain commitment: the off-chain answer stands, and it is a checked answer', () => {
  const r = applyOnchain([P, Q], { state: 'none', pending: [] });
  assert.deepEqual(r.keys, [P, Q]);
  assert.deepEqual(r.dropped, []);
  assert.equal(r.checked, true);
});

test('bound on-chain to P: only P keeps the address; another key that claims it off-chain is dropped with a reason', () => {
  const r = applyOnchain([Q, P], { state: 'bound', pubkey: P.pubkey, txid: 'f'.repeat(64), height: 900, pending: [] });
  assert.deepEqual(r.keys, [P]);
  assert.deepEqual(r.dropped, [{ ...Q, reason: 'onchain-bound-to-another-key' }]);
  assert.equal(r.checked, true);
});

test('bound on-chain to P, but P does not claim the address off-chain: nobody gets it (the Nostr key must say so too)', () => {
  const r = applyOnchain([], { state: 'bound', pubkey: P.pubkey, txid: 'f'.repeat(64), height: 900, pending: [] });
  assert.deepEqual(r.keys, []);
  const r2 = applyOnchain([Q], { state: 'bound', pubkey: P.pubkey, txid: 'f'.repeat(64), height: 900, pending: [] });
  assert.deepEqual(r2.keys, []);
});

test('revoked on-chain: every off-chain claim of the address is dropped, even one with a valid signed message', () => {
  const r = applyOnchain([P, Q], { state: 'revoked', pubkey: null, txid: 'e'.repeat(64), height: 905, pending: [] });
  assert.deepEqual(r.keys, []);
  assert.deepEqual(r.dropped, [{ ...P, reason: 'onchain-revoked' }, { ...Q, reason: 'onchain-revoked' }]);
});

test('chain state unknown: the off-chain answer stands but is marked not checked, with the reason', () => {
  const r = applyOnchain([P], { state: 'unknown', reason: 'only 1 of 3 servers answered' });
  assert.deepEqual(r.keys, [P]);
  assert.equal(r.checked, false);
  assert.match(r.reason, /1 of 3/);
});

test('an unconfirmed commitment changes nothing yet, but is reported', () => {
  const pending = [{ txid: 'd'.repeat(64), height: 0, pubkey: null }];
  const r = applyOnchain([P], { state: 'none', pending });
  assert.deepEqual(r.keys, [P]);
  assert.deepEqual(r.pending, pending);
});

test('a state it does not know is refused, not guessed', () => {
  assert.throws(() => applyOnchain([P], { state: 'maybe' }), /state/);
  assert.throws(() => applyOnchain([P], null), /state/);
});
