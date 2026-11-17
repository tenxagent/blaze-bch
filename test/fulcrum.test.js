// Reading commitments from several Electrum-protocol (Fulcrum) servers: union of histories (one server cannot hide a revocation),
// disagreement on a commitment's height ⇒ 'unknown', too few servers ⇒ 'unknown', a server serving wrong bytes is named and skipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { lookupOnchain, DEFAULT_FULCRUM } from '../src/fulcrum.js';
import { buildCommitmentTx } from '../src/committx.js';
import { p2pkhScript, scripthash } from '../src/commit.js';
import { serializeTx, txid } from '../src/bchtx.js';
import { hash160 } from '../src/bchmsg.js';
import { bytesToHex } from '../src/bytes.js';
import { BCH_SK, NOSTR_SK, nostrPubkey, bchAddress } from './helpers.js';

const PK = nostrPubkey(NOSTR_SK);
const ADDR = bchAddress(BCH_SK);
const SH = scripthash(ADDR);
let seq = 0;
function signed(pubkey) {
  const parentRaw = serializeTx({
    version: 2,
    inputs: [{ prevTxid: bytesToHex(new Uint8Array(32).fill(++seq)), vout: 0, script: Uint8Array.of(0x51), sequence: 0xffffffff }],
    outputs: [{ value: 30000n, script: p2pkhScript(hash160(secp256k1.getPublicKey(BCH_SK, true))) }],
    locktime: 0,
  });
  const { raw } = buildCommitmentTx({ sk: BCH_SK, utxos: [{ txid: txid(parentRaw), vout: 0, value: 30000n }], pubkey });
  return { id: txid(raw), raw: bytesToHex(raw), parentId: txid(parentRaw), parentRaw: bytesToHex(parentRaw) };
}
const BIND = signed(PK);
const REVOKE = signed(null);

// A fake Fulcrum: history per scripthash + raw txs; `swap` serves other bytes for one txid; `silent` never answers.
function fakeServer({ history = [], swap = {}, silent = false }) {
  const txs = {};
  for (const t of [BIND, REVOKE]) { txs[t.id] = t.raw; txs[t.parentId] = t.parentRaw; }
  return {
    silent,
    calls: [],
    handle(method, params) {
      this.calls.push(method);
      if (method === 'server.version') return ['Fulcrum fake', '1.4'];
      if (method === 'blockchain.scripthash.get_history') return params[0] === SH ? history : [];
      if (method === 'blockchain.transaction.get') return swap[params[0]] ?? txs[params[0]];
      throw new Error(`unexpected ${method}`);
    },
  };
}
function fakeConnect(servers) {
  return (url) => {
    const srv = servers[url];
    const ws = {
      send(data) {
        if (srv.silent) return;
        const { id, method, params } = JSON.parse(data);
        queueMicrotask(() => {
          let reply;
          try { reply = { jsonrpc: '2.0', id, result: srv.handle(method, params) }; } catch (e) { reply = { jsonrpc: '2.0', id, error: { message: e.message } }; }
          ws.onmessage?.({ data: JSON.stringify(reply) });
        });
      },
      close() {},
    };
    queueMicrotask(() => (srv ? ws.onopen?.({}) : ws.onerror?.(new Error('connect failed'))));
    return ws;
  };
}
const h = (t, height) => ({ tx_hash: t.id, height });
const run = (servers, opts = {}) => lookupOnchain(ADDR, { servers: Object.keys(servers), connect: fakeConnect(servers), timeoutMs: 200, ...opts });

test('default server list: wss only, three different operators', () => {
  assert.ok(DEFAULT_FULCRUM.length >= 3);
  assert.ok(DEFAULT_FULCRUM.every((u) => u.startsWith('wss://')));
  assert.equal(new Set(DEFAULT_FULCRUM.map((u) => new URL(u).hostname.split('.').slice(-2).join('.'))).size, DEFAULT_FULCRUM.length);
});

test('two honest servers: bound, asked by scripthash, both named', async () => {
  const a = fakeServer({ history: [h(BIND, 900)] });
  const b = fakeServer({ history: [h(BIND, 900)] });
  const r = await run({ 'wss://a': a, 'wss://b': b });
  assert.equal(r.state, 'bound');
  assert.equal(r.pubkey, PK);
  assert.equal(r.txid, BIND.id);
  assert.deepEqual(r.servers.sort(), ['wss://a', 'wss://b']);
  assert.ok(a.calls.includes('blockchain.scripthash.get_history'));
});

test('one server hides the newer revocation: the union still sees it (revoked), and the hiding server is named', async () => {
  const honest = fakeServer({ history: [h(BIND, 900), h(REVOKE, 905)] });
  const hider = fakeServer({ history: [h(BIND, 900)] });
  for (const servers of [{ 'wss://hider': hider, 'wss://honest': honest }, { 'wss://honest': honest, 'wss://hider': hider }]) {
    const r = await run(servers);
    assert.equal(r.state, 'revoked');
    assert.deepEqual(r.hidden, [{ txid: REVOKE.id, by: ['wss://hider'] }]);
  }
});

test('servers disagree on a commitment\'s height ⇒ unknown (no answer is better than a wrong one)', async () => {
  const r = await run({ 'wss://a': fakeServer({ history: [h(BIND, 900), h(REVOKE, 905)] }), 'wss://b': fakeServer({ history: [h(BIND, 900), h(REVOKE, 899)] }) });
  assert.equal(r.state, 'unknown');
  assert.match(r.reason, /disagree/);
});

test('fewer than minServers answer ⇒ unknown; a silent server costs only its timeout', async () => {
  const t0 = Date.now();
  const r = await run({ 'wss://a': fakeServer({ history: [h(BIND, 900)] }), 'wss://silent': fakeServer({ silent: true }), 'wss://dead': undefined });
  assert.equal(r.state, 'unknown');
  assert.match(r.reason, /1 of 3/);
  assert.ok(Date.now() - t0 < 1500);
  const ok = await run({ 'wss://a': fakeServer({ history: [h(BIND, 900)] }), 'wss://silent': fakeServer({ silent: true }) }, { minServers: 1 });
  assert.equal(ok.state, 'bound');
});

test('a server that serves other bytes for a txid is named as a liar and the bytes are taken from another server', async () => {
  const liar = fakeServer({ history: [h(BIND, 900)], swap: { [BIND.id]: REVOKE.raw } });
  const honest = fakeServer({ history: [h(BIND, 900)] });
  const r = await run({ 'wss://liar': liar, 'wss://honest': honest });
  assert.equal(r.state, 'bound');
  assert.deepEqual(r.liars, ['wss://liar']);
});

test('no history anywhere ⇒ none (the off-chain binding stands alone)', async () => {
  const r = await run({ 'wss://a': fakeServer({}), 'wss://b': fakeServer({}) });
  assert.equal(r.state, 'none');
});
