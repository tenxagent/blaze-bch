// Read an address's on-chain commitment from several Electrum-protocol (Fulcrum) servers over WebSocket, in a browser or Node 22.
// Trust: keys sign, servers only list and order. Every tx is hashed and every commitment's signature is checked here (commit.js), so
// a server cannot invent or alter one. A server CAN hide a tx or misstate its height, so: the histories of all answering servers are
// joined (one honest server is enough to show a revocation), and if the servers that list a commitment disagree on its height, the
// answer is 'unknown' rather than a guess. Fewer than minServers answering ⇒ 'unknown'.
import { scripthash, readCommitment, onchainState } from './commit.js';
import { parseTx, txid as txidOf } from './bchtx.js';
import { hexToBytes } from './bytes.js';

// One server per operator (bch.imaginary.cash and electrum.imaginary.cash are the same operator, so only one of them is listed).
export const DEFAULT_FULCRUM = ['wss://bch.imaginary.cash:50004', 'wss://bch.loping.net:50004', 'wss://fulcrum.greyh.at:50004'];

const defaults = (opts = {}) => ({ servers: DEFAULT_FULCRUM, minServers: 2, connect: (url) => new WebSocket(url), timeoutMs: 8000, ...opts });

// A JSON-RPC session; every call has its own timeout. Resolves to null if the server cannot be reached in time.
function open(url, { connect, timeoutMs }) {
  return new Promise((resolve) => {
    let ws;
    let id = 0;
    const waiting = new Map();
    const timer = setTimeout(() => resolve(null), timeoutMs);
    const session = {
      url,
      call(method, params) {
        return new Promise((res, rej) => {
          const n = ++id;
          const t = setTimeout(() => { waiting.delete(n); rej(new Error(`${url}: ${method} timed out`)); }, timeoutMs);
          waiting.set(n, { res, rej, t });
          try { ws.send(JSON.stringify({ jsonrpc: '2.0', id: n, method, params })); } catch (e) { clearTimeout(t); waiting.delete(n); rej(e); }
        });
      },
      close() { try { ws.close(); } catch {} },
    };
    try { ws = connect(url); } catch { clearTimeout(timer); return resolve(null); }
    ws.onopen = () => { clearTimeout(timer); resolve(session); };
    ws.onerror = () => { clearTimeout(timer); resolve(null); };
    ws.onmessage = (m) => {
      let d;
      try { d = JSON.parse(m.data); } catch { return; }
      const w = waiting.get(d.id);
      if (!w) return;
      waiting.delete(d.id);
      clearTimeout(w.t);
      if (d.error) w.rej(new Error(`${url}: ${d.error.message ?? 'error'}`)); else w.res(d.result);
    };
  });
}

async function historyFrom(url, sh, opts) {
  const s = await open(url, opts);
  if (!s) return null;
  try {
    await s.call('server.version', ['blaze-bch', '1.4']);
    const hist = await s.call('blockchain.scripthash.get_history', [sh]);
    if (!Array.isArray(hist)) throw new Error('bad history');
    return { session: s, history: new Map(hist.map((x) => [x.tx_hash, x.height])) };
  } catch {
    s.close();
    return null;
  }
}

// Fetch a tx's bytes from the given sessions in order, keeping the first whose bytes hash to the txid; others that answered wrong are liars.
async function fetchTx(id, sessions, liars) {
  for (const s of sessions) {
    let hex;
    try { hex = await s.call('blockchain.transaction.get', [id, false]); } catch { continue; }
    let raw;
    try { raw = hexToBytes(hex); } catch { liars.add(s.url); continue; }
    if (txidOf(raw) === id) return raw;
    liars.add(s.url);
  }
  return null;
}

// → { state: 'bound' | 'revoked' | 'none' | 'unknown', pubkey?, txid?, height?, pending?, reason?, servers, hidden, liars }
export async function lookupOnchain(address, opts) {
  const o = defaults(opts);
  const sh = scripthash(address);
  const views = (await Promise.all(o.servers.map(async (url) => ({ url, view: await historyFrom(url, sh, o) })))).filter((v) => v.view);
  const servers = views.map((v) => v.url);
  const liars = new Set();
  const done = (r) => {
    for (const v of views) v.view.session.close();
    return { ...r, servers, hidden: r.hidden ?? [], liars: [...liars] };
  };
  if (views.length < o.minServers) return done({ state: 'unknown', reason: `only ${views.length} of ${o.servers.length} servers answered` });
  const ids = [...new Set(views.flatMap((v) => [...v.view.history.keys()]))];
  const entries = [];
  const hidden = [];
  for (const id of ids) {
    const listing = views.filter((v) => v.view.history.has(id));
    const raw = await fetchTx(id, listing.map((v) => v.view.session), liars);
    if (!raw) return done({ state: 'unknown', reason: `no server served the bytes of ${id}` });
    let c = null;
    try { c = readCommitment(parseTx(raw)); } catch {}
    const entry = { txid: id, raw, height: listing[0].view.history.get(id) };
    if (c) {
      const heights = new Set(listing.map((v) => v.view.history.get(id)));
      if (heights.size > 1) return done({ state: 'unknown', reason: `servers disagree on the height of commitment ${id}` });
      const notListing = views.filter((v) => !v.view.history.has(id)).map((v) => v.url);
      if (notListing.length) hidden.push({ txid: id, by: notListing });
      const prev = parseTx(raw).inputs[0].prevTxid;
      entry.parentRaw = await fetchTx(prev, views.map((v) => v.view.session), liars);
    }
    entries.push(entry);
  }
  try {
    return done({ ...onchainState(address, entries), hidden });
  } catch (e) {
    return done({ state: 'unknown', reason: e.message, hidden });
  }
}
