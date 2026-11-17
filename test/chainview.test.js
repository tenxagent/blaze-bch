// The lines the demo page shows after "Check the chain": one plain sentence per on-chain state, built from lookupOnchain's result and
// applyOnchain's verdict, so the page only places them (textContent) and the wording is tested here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chainLines } from '../src/chainview.js';
import { applyOnchain } from '../src/commit.js';

const P = { pubkey: 'a'.repeat(64), npub: 'npub1pp' };
const Q = { pubkey: 'b'.repeat(64), npub: 'npub1qq' };
const npubOf = (pk) => ({ [P.pubkey]: P.npub, [Q.pubkey]: Q.npub })[pk] ?? 'npub1other';
const TX = '1234567890ab'.padEnd(64, 'c');
const lines = (keys, onchain) => chainLines(onchain, applyOnchain(keys, onchain), npubOf);

test('none: the relay answer stands', () => {
  assert.deepEqual(lines([P], { state: 'none', pending: [] }), [{ text: 'On chain: no commitment for this address. The relay answer stands.', cls: 'muted' }]);
});

test('bound to a key that also claims it: confirmed, with block and short txid; another claimer is named as dropped', () => {
  assert.deepEqual(lines([P, Q], { state: 'bound', pubkey: P.pubkey, txid: TX, height: 977800, pending: [] }), [
    { text: '✓ On chain: bound to npub1pp (block 977800, tx 1234567890ab…).', cls: 'ok' },
    { text: '✗ npub1qq: the address\'s key bound it to another npub on chain, so this claim does not count.', cls: 'bad' },
  ]);
});

test('bound to a key that does not claim it on the relays: nothing counts, and the page says why', () => {
  assert.deepEqual(lines([], { state: 'bound', pubkey: Q.pubkey, txid: TX, height: 977800, pending: [] }), [
    { text: '✗ On chain: bound to npub1qq (block 977800, tx 1234567890ab…), but that npub does not claim this address on the relays, so nothing counts.', cls: 'bad' },
  ]);
});

test('revoked: no relay claim counts', () => {
  assert.deepEqual(lines([P], { state: 'revoked', pubkey: null, txid: TX, height: 977801, pending: [] }), [
    { text: '✗ On chain: the address\'s key revoked its link in block 977801 (tx 1234567890ab…). No relay claim of this address counts.', cls: 'bad' },
  ]);
});

test('unknown: says the chain was not checked and why, and that the relay answer is unconfirmed', () => {
  assert.deepEqual(lines([P], { state: 'unknown', reason: 'only 1 of 3 servers answered' }), [
    { text: 'On chain: not checked (only 1 of 3 servers answered). The relay answer above is not confirmed by the chain.', cls: 'muted' },
  ]);
});

test('pending commitments get one extra line', () => {
  const pending = [{ txid: TX, height: 0, pubkey: null }, { txid: TX, height: -1, pubkey: P.pubkey }];
  const out = lines([P], { state: 'none', pending });
  assert.equal(out.length, 2);
  assert.deepEqual(out[1], { text: '2 unconfirmed commitments are waiting for a block; they count once confirmed.', cls: 'muted' });
  assert.equal(lines([P], { state: 'none', pending: pending.slice(0, 1) })[1].text, '1 unconfirmed commitment is waiting for a block; it counts once confirmed.');
});
