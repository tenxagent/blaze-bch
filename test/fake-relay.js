// In-memory Nostr relay + WebSocket-like client for tests (no network). Supports REQ filters on kinds, authors, #i, limit;
// EVENT -> stores it (replaceable kind 10011 keeps only the newest per pubkey unless keepOld) and answers OK.
export class FakeRelay {
  constructor({ keepOld = false, silent = false, rejectWrites = false } = {}) {
    Object.assign(this, { keepOld, silent, rejectWrites, events: [], reqs: [] });
  }
  matches(f, e) {
    if (f.kinds && !f.kinds.includes(e.kind)) return false;
    if (f.authors && !f.authors.includes(e.pubkey)) return false;
    if (f['#i'] && !e.tags.some((t) => t[0] === 'i' && f['#i'].includes(t[1]))) return false;
    return true;
  }
  handle(msg, reply) {
    const [type, ...rest] = msg;
    if (this.silent) return;
    if (type === 'REQ') {
      const [sub, ...filters] = rest;
      this.reqs.push(filters);
      const hits = this.events.filter((e) => filters.some((f) => this.matches(f, e)))
        .sort((a, b) => b.created_at - a.created_at);
      for (const e of hits) reply(['EVENT', sub, e]);
      reply(['EOSE', sub]);
    } else if (type === 'EVENT') {
      const [e] = rest;
      if (this.rejectWrites) return reply(['OK', e.id, false, 'blocked: test relay']);
      if (!this.keepOld) this.events = this.events.filter((x) => !(x.kind === e.kind && x.pubkey === e.pubkey && e.kind === 10011));
      this.events.push(e);
      reply(['OK', e.id, true, '']);
    }
  }
}

// connect(url) factory over a map url -> FakeRelay; unknown urls fail like a dead relay.
export function fakeConnect(relays) {
  return (url) => {
    const relay = relays[url];
    const ws = {
      readyState: 0,
      send(data) {
        queueMicrotask(() => relay.handle(JSON.parse(data), (m) => ws.onmessage?.({ data: JSON.stringify(m) })));
      },
      close() {
        ws.readyState = 3;
        queueMicrotask(() => ws.onclose?.({}));
      },
    };
    queueMicrotask(() => {
      if (!relay) return ws.onerror?.(new Error('connect failed'));
      ws.readyState = 1;
      ws.onopen?.({});
    });
    return ws;
  };
}
