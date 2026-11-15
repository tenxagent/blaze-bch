// Relay I/O: publish a signed event, forward lookup (npub -> addresses) and reverse lookup (address -> npubs).
// No server of ours: everything is read from public relays and verified locally. Relays are queried in parallel,
// each with its own timeout, so a dead or silent relay only costs its timeout.
import { verifyEvent } from './nostr.js';
import { verifyBinding, BINDING_KIND } from './binding.js';
import { decodeCashaddr } from './cashaddr.js';

// The six public relays the 2026-11-15 live test passed on (publish, #i reverse lookup, replacement).
export const DEFAULT_RELAYS = ['wss://nos.lol', 'wss://relay.primal.net', 'wss://offchain.pub', 'wss://nostr.mom', 'wss://relay.nostr.net',
  'wss://relay.snort.social'];

const defaults = (opts = {}) => ({ connect: (url) => new WebSocket(url), timeoutMs: 8000, ...opts });
let subCounter = 0;

function talk(url, first, onMessage, { connect, timeoutMs }) {
  return new Promise((resolve) => {
    let ws;
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        ws?.close();
      } catch {}
      resolve(value);
    };
    const timer = setTimeout(() => finish(undefined), timeoutMs);
    try {
      ws = connect(url);
    } catch {
      return finish(undefined);
    }
    ws.onopen = () => {
      try {
        ws.send(JSON.stringify(first));
      } catch {
        finish(undefined);
      }
    };
    ws.onmessage = (m) => {
      let msg;
      try {
        msg = JSON.parse(m.data);
      } catch {
        return;
      }
      if (Array.isArray(msg)) onMessage(msg, finish);
    };
    ws.onerror = () => finish(undefined);
    ws.onclose = () => finish(undefined);
  });
}

async function query(urls, filter, opts) {
  const per = await Promise.all(urls.map((url) => {
    const sub = `blaze${++subCounter}`;
    const events = [];
    return talk(url, ['REQ', sub, filter], (msg, finish) => {
      if (msg[0] === 'EVENT' && msg[1] === sub && msg[2] && typeof msg[2] === 'object') events.push(msg[2]);
      else if ((msg[0] === 'EOSE' || msg[0] === 'CLOSED') && msg[1] === sub) finish();
    }, opts).then(() => events);
  }));
  const byId = new Map();
  for (const e of per.flat()) if (typeof e.id === 'string' && !byId.has(e.id)) byId.set(e.id, e);
  return [...byId.values()];
}

// NIP-01 replaceable rule: newest created_at wins; on a tie, the lowest id.
const newestFirst = (a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

export async function publish(event, urls, opts) {
  const v = verifyEvent(event);
  if (!v.ok) throw new Error(`refusing to publish: ${v.reason}`);
  const o = defaults(opts);
  return Promise.all(urls.map(async (url) => {
    const r = await talk(url, ['EVENT', event], (msg, finish) => {
      if (msg[0] === 'OK' && msg[1] === event.id) finish({ ok: msg[2] === true, message: String(msg[3] ?? '') });
    }, o);
    return { url, ok: r?.ok ?? false, message: r ? r.message : 'no answer' };
  }));
}

// npub/pubkey -> the newest VALID kind 10011 event of that author, with its binding result; null if none.
export async function lookupByPubkey(pubkey, urls, opts) {
  const events = await query(urls, { kinds: [BINDING_KIND], authors: [pubkey] }, defaults(opts));
  const own = events.filter((e) => e.pubkey === pubkey && e.kind === BINDING_KIND && verifyEvent(e).ok).sort(newestFirst);
  if (!own.length) return null;
  return { event: own[0], ...verifyBinding(own[0]) };
}

// cashaddr -> [{ pubkey, npub }] of the keys whose CURRENT (newest) binding still proves this address.
export async function lookupByAddress(address, urls, opts) {
  const o = defaults(opts);
  decodeCashaddr(address); // throws on a malformed address
  const canonical = address.toLowerCase();
  const events = await query(urls, { kinds: [BINDING_KIND], '#i': [`bch:${canonical}`] }, o);
  const candidates = [...new Set(events.filter((e) => verifyBinding(e).verified?.includes(canonical)).map((e) => e.pubkey))];
  const out = [];
  for (const pk of candidates) {
    const current = await lookupByPubkey(pk, urls, o);
    if (current?.verified?.includes(canonical)) out.push({ pubkey: pk, npub: current.npub });
  }
  return out;
}

// Relay list from a page's query string (?relays=a,b). wss:// is accepted for any host; plain ws:// only for localhost (local tests).
// Nothing valid => the defaults.
export function relaysFromQuery(search) {
  const raw = new URLSearchParams(search).get('relays');
  if (!raw) return DEFAULT_RELAYS;
  const ok = raw.split(',').map((s) => s.trim()).filter((s) => {
    try {
      const u = new URL(s);
      return u.protocol === 'wss:' || (u.protocol === 'ws:' && ['127.0.0.1', 'localhost'].includes(u.hostname));
    } catch {
      return false;
    }
  });
  return ok.length ? ok : DEFAULT_RELAYS;
}
