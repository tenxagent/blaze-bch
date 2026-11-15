import { test } from 'node:test';
import assert from 'node:assert/strict';
import { publish, lookupByPubkey, lookupByAddress } from '../src/relay.js';
import { verificationText } from '../src/binding.js';
import { npubEncode } from '../src/bech32.js';
import { FakeRelay, fakeConnect } from './fake-relay.js';
import { NOSTR_SK, BCH_SK, OTHER_SK, keyFrom, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';

const pk = nostrPubkey(NOSTR_SK);
const npub = npubEncode(pk);
const addr = bchAddress(BCH_SK);
const claim = (bchSk = BCH_SK, forNpub = npub) => ['i', `bch:${bchAddress(bchSk)}`, signBch(bchSk, verificationText(forNpub))];
const binding = (tags, created_at = 1763128800, sk = NOSTR_SK) => signEvent(sk, { tags, created_at });
const URLS = ['wss://a', 'wss://b', 'wss://c'];
const setup = (opts = {}) => {
  const relays = Object.fromEntries(URLS.map((u) => [u, new FakeRelay(opts[u])]));
  return { relays, connect: fakeConnect(relays), timeoutMs: 200 };
};

test('publish sends the event to every relay and reports each OK', async () => {
  const { relays, connect, timeoutMs } = setup({ 'wss://c': { rejectWrites: true } });
  const ev = binding([claim()]);
  const r = await publish(ev, URLS, { connect, timeoutMs });
  assert.deepEqual(r.map((x) => [x.url, x.ok]), [['wss://a', true], ['wss://b', true], ['wss://c', false]]);
  assert.equal(relays['wss://a'].events[0].id, ev.id);
});

test('publish refuses an event that does not verify (never send garbage)', async () => {
  const { connect, timeoutMs } = setup();
  await assert.rejects(publish({ ...binding([claim()]), content: 'x' }, URLS, { connect, timeoutMs }), /bad-id/);
});

test('forward lookup: the NEWEST valid binding across relays wins (a stale relay cannot roll back)', async () => {
  const { relays, connect, timeoutMs } = setup({ 'wss://b': { keepOld: true } });
  const old = binding([claim()], 1763128800);
  const now = binding([claim(OTHER_SK)], 1763128900);
  relays['wss://a'].events.push(now);
  relays['wss://b'].events.push(old);
  const r = await lookupByPubkey(pk, URLS, { connect, timeoutMs });
  assert.equal(r.event.id, now.id);
  assert.deepEqual(r.verified, [bchAddress(OTHER_SK)]);
});

test('forward lookup asks for exactly kind 10011 from that author', async () => {
  const { relays, connect, timeoutMs } = setup();
  await lookupByPubkey(pk, URLS, { connect, timeoutMs });
  assert.deepEqual(relays['wss://a'].reqs[0], [{ kinds: [10011], authors: [pk] }]);
});

test('forward lookup ignores forged events and returns null when nothing valid exists', async () => {
  const { relays, connect, timeoutMs } = setup();
  relays['wss://a'].events.push({ ...binding([claim()], 1763129999), sig: '00'.repeat(64) });
  assert.equal(await lookupByPubkey(pk, URLS, { connect, timeoutMs }), null);
});

test('reverse lookup: address -> npub via the #i filter, verified locally', async () => {
  const { relays, connect, timeoutMs } = setup();
  relays['wss://a'].events.push(binding([claim()]));
  const r = await lookupByAddress(addr, URLS, { connect, timeoutMs });
  assert.deepEqual(r, [{ pubkey: pk, npub }]);
  assert.deepEqual(relays['wss://a'].reqs[0], [{ kinds: [10011], '#i': [`bch:${addr}`] }]);
});

test('reverse lookup drops a pubkey whose NEWEST binding no longer names the address (revoked)', async () => {
  const { relays, connect, timeoutMs } = setup({ 'wss://b': { keepOld: true } });
  relays['wss://b'].events.push(binding([claim()], 1763128800));
  relays['wss://a'].events.push(binding([['i', 'github:someone', 'gist']], 1763128900));
  assert.deepEqual(await lookupByAddress(addr, URLS, { connect, timeoutMs }), []);
});

test('reverse lookup ignores someone who copied the claim tag without owning the BCH key', async () => {
  const { relays, connect, timeoutMs } = setup();
  const thief = keyFrom(' / thief');
  relays['wss://a'].events.push(binding([claim()], 1763128800, thief)); // proof names OUR npub, event is the thief's
  assert.deepEqual(await lookupByAddress(addr, URLS, { connect, timeoutMs }), []);
});

test('dead and silent relays do not block a lookup (timeout per relay)', async () => {
  const { relays, timeoutMs } = setup({ 'wss://b': { silent: true } });
  relays['wss://a'].events.push(binding([claim()]));
  const connect = fakeConnect({ 'wss://a': relays['wss://a'], 'wss://b': relays['wss://b'] }); // wss://c is dead
  const t0 = Date.now();
  const r = await lookupByPubkey(pk, URLS, { connect, timeoutMs });
  assert.deepEqual(r.verified, [addr]);
  assert.ok(Date.now() - t0 < timeoutMs * 3, 'relays are queried in parallel');
});

test('DEFAULT_RELAYS = the six relays the live test passed on, all wss://', async () => {
  const { DEFAULT_RELAYS } = await import('../src/relay.js');
  assert.equal(DEFAULT_RELAYS.length, 6);
  assert.ok(DEFAULT_RELAYS.every((u) => u.startsWith('wss://')));
});

test('relaysFromQuery: ?relays= overrides the defaults; wss:// anywhere, plain ws:// only for localhost', async () => {
  const { relaysFromQuery, DEFAULT_RELAYS } = await import('../src/relay.js');
  assert.deepEqual(relaysFromQuery(''), DEFAULT_RELAYS);
  assert.deepEqual(relaysFromQuery('?relays=wss://a.example,ws://127.0.0.1:7777'), ['wss://a.example', 'ws://127.0.0.1:7777']);
  assert.deepEqual(relaysFromQuery('?relays=ws://localhost:1'), ['ws://localhost:1']);
  assert.deepEqual(relaysFromQuery('?relays=ws://evil.example,https://x.example'), DEFAULT_RELAYS, 'no valid relay => defaults');
  assert.deepEqual(relaysFromQuery('?relays=ws://evil.example,wss://ok.example'), ['wss://ok.example']);
});
