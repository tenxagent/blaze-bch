import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startLocalRelay } from './local-relay.mjs';
import { publish, lookupByPubkey, lookupByAddress } from '../src/relay.js';
import { verificationText } from '../src/binding.js';
import { npubEncode } from '../src/bech32.js';
import { NOSTR_SK, BCH_SK, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';

test('src/relay.js over REAL WebSockets (local relay): publish, forward + reverse lookup, revocation', async () => {
  const r = await startLocalRelay();
  try {
    const pk = nostrPubkey(NOSTR_SK);
    const addr = bchAddress(BCH_SK);
    const ev = signEvent(NOSTR_SK, { tags: [['i', `bch:${addr}`, signBch(BCH_SK, verificationText(npubEncode(pk)))]], created_at: 1763200000 });
    const opts = { timeoutMs: 3000 };
    assert.deepEqual((await publish(ev, [r.url], opts)).map((x) => x.ok), [true]);
    assert.deepEqual((await lookupByPubkey(pk, [r.url], opts)).verified, [addr]);
    assert.deepEqual((await lookupByAddress(addr, [r.url], opts)).map((x) => x.pubkey), [pk]);
    await publish(signEvent(NOSTR_SK, { tags: [], created_at: 1763200001 }), [r.url], opts);
    assert.deepEqual(await lookupByAddress(addr, [r.url], opts), []);
  } finally {
    await r.close();
  }
});
