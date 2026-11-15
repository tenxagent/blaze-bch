// Test-only local Nostr relay on 127.0.0.1: a minimal WebSocket server (RFC 6455 handshake, unfragmented text frames, close, ping)
// in front of the in-memory FakeRelay. Lets tests and the headless browser run publish + lookups over REAL sockets, with no public post.
//   node test/local-relay.mjs <port>       (standalone, for the browser test)
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { FakeRelay } from './fake-relay.js';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function frame(opcode, payload) {
  const len = payload.length;
  const head = len < 126 ? Buffer.from([0x80 | opcode, len])
    : len < 65536 ? Buffer.from([0x80 | opcode, 126, len >> 8, len & 255])
      : Buffer.concat([Buffer.from([0x80 | opcode, 127]), (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(len)); return b; })()]);
  return Buffer.concat([head, payload]);
}

export function startLocalRelay(port = 0, relay = new FakeRelay()) {
  const server = createServer((req, res) => res.writeHead(426).end('websocket only'));
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) return socket.destroy();
    const accept = createHash('sha1').update(key + GUID).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    const send = (msg) => socket.writable && socket.write(frame(1, Buffer.from(JSON.stringify(msg))));
    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const opcode = buf[0] & 15;
        const masked = buf[1] & 128;
        let len = buf[1] & 127;
        let off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
        const maskLen = masked ? 4 : 0;
        if (buf.length < off + maskLen + len) return;
        const mask = buf.subarray(off, off + maskLen);
        const data = Buffer.from(buf.subarray(off + maskLen, off + maskLen + len));
        if (masked) for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
        buf = buf.subarray(off + maskLen + len);
        if (opcode === 8) { socket.end(frame(8, Buffer.alloc(0))); return; }
        if (opcode === 9) { socket.write(frame(10, data)); continue; }
        if (opcode !== 1) continue;
        try {
          relay.handle(JSON.parse(data.toString('utf8')), send);
        } catch {
          send(['NOTICE', 'bad message']);
        }
      }
    });
    socket.on('error', () => {});
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve({ server, relay, url: `ws://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) })));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { url } = await startLocalRelay(Number(process.argv[2] || 0));
  console.log(`local relay ${url}`);
}
