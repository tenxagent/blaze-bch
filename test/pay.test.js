import { test } from 'node:test';
import assert from 'node:assert/strict';
import { paymentUri, resolvePayment } from '../src/pay.js';
import { verificationText } from '../src/binding.js';
import { npubEncode } from '../src/bech32.js';
import { FakeRelay, fakeConnect } from './fake-relay.js';
import { NOSTR_SK, BCH_SK, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';

const addr = bchAddress(BCH_SK);
const npub = npubEncode(nostrPubkey(NOSTR_SK));

test('payment URI is the cashaddr itself, plus optional amount (BCH, max 8 decimals) and label', () => {
  assert.equal(paymentUri(addr), addr);
  assert.equal(paymentUri(addr, { amount: '0.001' }), `${addr}?amount=0.001`);
  assert.equal(paymentUri(addr, { amount: '1.00000000' }), `${addr}?amount=1`);
  assert.equal(paymentUri(addr, { amount: 0.5, label: 'blaze test & co' }), `${addr}?amount=0.5&label=blaze%20test%20%26%20co`);
  assert.equal(paymentUri(addr.toUpperCase()), addr);
});

test('bad amounts and bad addresses are refused', () => {
  for (const amount of ['-1', '0', 'abc', '0.000000001', '1e3', Number.NaN]) {
    assert.throws(() => paymentUri(addr, { amount }), /amount/, String(amount));
  }
  assert.throws(() => paymentUri('bitcoincash:qqqq'), /cashaddr/);
});

test('resolvePayment: npub -> its verified address on the relays -> URI; null when nothing is bound', async () => {
  const relay = new FakeRelay();
  relay.events.push(signEvent(NOSTR_SK, { tags: [['i', `bch:${addr}`, signBch(BCH_SK, verificationText(npub))]] }));
  const opts = { connect: fakeConnect({ 'wss://a': relay }), timeoutMs: 200 };
  assert.deepEqual(await resolvePayment(npub, ['wss://a'], { ...opts, amount: '0.01' }),
    { address: addr, uri: `${addr}?amount=0.01` });
  assert.equal(await resolvePayment(npubEncode(nostrPubkey(BCH_SK)), ['wss://a'], opts), null);
});

test('resolvePayment with an on-chain check: a revoked address gives no URI (with the reason); unknown gives the URI marked not checked', async () => {
  const relay = new FakeRelay();
  relay.events.push(signEvent(NOSTR_SK, { tags: [['i', `bch:${addr}`, signBch(BCH_SK, verificationText(npub))]] }));
  const base = { connect: fakeConnect({ 'wss://a': relay }), timeoutMs: 200 };
  const asked = [];
  const chain = (state) => async (a) => { asked.push(a); return state; };
  const pk = nostrPubkey(NOSTR_SK);

  assert.deepEqual(await resolvePayment(npub, ['wss://a'], { ...base, onchain: chain({ state: 'none', pending: [] }) }),
    { address: addr, uri: addr, checked: true });
  assert.deepEqual(asked, [addr]);
  assert.deepEqual(await resolvePayment(npub, ['wss://a'], { ...base, onchain: chain({ state: 'bound', pubkey: pk, pending: [] }) }),
    { address: addr, uri: addr, checked: true });
  assert.deepEqual(await resolvePayment(npub, ['wss://a'], { ...base, onchain: chain({ state: 'revoked', pubkey: null, pending: [] }) }),
    { address: addr, uri: null, checked: true, reason: 'onchain-revoked' });
  assert.deepEqual(await resolvePayment(npub, ['wss://a'], { ...base, onchain: chain({ state: 'bound', pubkey: 'c'.repeat(64), pending: [] }) }),
    { address: addr, uri: null, checked: true, reason: 'onchain-bound-to-another-key' });
  assert.deepEqual(await resolvePayment(npub, ['wss://a'], { ...base, amount: '0.5', onchain: chain({ state: 'unknown', reason: 'only 1 of 3 servers answered' }) }),
    { address: addr, uri: `${addr}?amount=0.5`, checked: false, reason: 'only 1 of 3 servers answered' });
});
