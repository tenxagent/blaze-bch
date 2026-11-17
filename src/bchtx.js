// BCH transaction bytes (BCH has no segwit): parse, serialize, txid, and the FORKID signature hash (BIP143-style digest, as BCH nodes
// compute it for SIGHASH_FORKID). Portable: no Node-only APIs. Strict: non-canonical lengths, short input and trailing bytes are refused.
import { sha256d } from './cashaddr.js';
import { bytesToHex, hexToBytes } from './bytes.js';

const reversed = (u8) => Uint8Array.from(u8).reverse();
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const u32le = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0, true); return b; };
const i32le = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v, true); return b; };
const i64le = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); return b; };

export function varint(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  if (n <= 0xffffffff) return concat([Uint8Array.of(0xfe), u32le(n)]);
  throw new Error('bchtx: length too large');
}
const varbytes = (b) => concat([varint(b.length), b]);

function reader(b) {
  let o = 0;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const need = (n) => { if (o + n > b.length) throw new Error('bchtx: too short'); };
  const r = {
    bytes(n) { need(n); const s = b.slice(o, o + n); o += n; return s; },
    u8() { need(1); return b[o++]; },
    u32() { need(4); const v = dv.getUint32(o, true); o += 4; return v; },
    i32() { need(4); const v = dv.getInt32(o, true); o += 4; return v; },
    i64() { need(8); const v = dv.getBigInt64(o, true); o += 8; return v; },
    varint() {
      const first = r.u8();
      if (first < 0xfd) return first;
      let v;
      if (first === 0xfd) { need(2); v = dv.getUint16(o, true); o += 2; if (v < 0xfd) throw new Error('bchtx: non-canonical length'); return v; }
      if (first === 0xfe) { v = r.u32(); if (v <= 0xffff) throw new Error('bchtx: non-canonical length'); return v; }
      throw new Error('bchtx: length too large');
    },
    end() { if (o !== b.length) throw new Error('bchtx: trailing bytes'); },
  };
  return r;
}

// prevTxid is in display order (as explorers and txid() print it); scripts are raw bytes; value is satoshis as a BigInt.
export function parseTx(bytes) {
  const r = reader(bytes);
  const version = r.i32();
  const inputs = Array.from({ length: r.varint() }, () => ({
    prevTxid: bytesToHex(reversed(r.bytes(32))),
    vout: r.u32(),
    script: r.bytes(r.varint()),
    sequence: r.u32(),
  }));
  const outputs = Array.from({ length: r.varint() }, () => ({ value: r.i64(), script: r.bytes(r.varint()) }));
  const locktime = r.u32();
  r.end();
  return { version, inputs, outputs, locktime };
}

const outpoint = (i) => concat([reversed(hexToBytes(i.prevTxid)), u32le(i.vout)]);
const outputBytes = (o) => concat([i64le(o.value), varbytes(o.script)]);

export function serializeTx(tx) {
  return concat([
    i32le(tx.version),
    varint(tx.inputs.length), ...tx.inputs.map((i) => concat([outpoint(i), varbytes(i.script), u32le(i.sequence)])),
    varint(tx.outputs.length), ...tx.outputs.map(outputBytes),
    u32le(tx.locktime),
  ]);
}

export const txid = (bytes) => bytesToHex(reversed(sha256d(bytes)));

// The digest a BCH node signs for input nIn when hashType carries SIGHASH_FORKID (0x40): base type = hashType & 0x1f
// (2 = NONE, 3 = SINGLE, anything else = ALL), 0x80 = ANYONECANPAY. Returns the raw sha256d (sign this; BCHN prints it reversed).
export function sighashForkid(tx, nIn, scriptCode, amount, hashType) {
  if (!(hashType & 0x40)) throw new Error('bchtx: hash type lacks the FORKID bit');
  if (!Number.isInteger(nIn) || nIn < 0 || nIn >= tx.inputs.length) throw new Error('bchtx: no such input');
  const base = hashType & 0x1f;
  const anyoneCanPay = (hashType & 0x80) !== 0;
  const single = base === 3;
  const none = base === 2;
  const zero = new Uint8Array(32);
  const hashPrevouts = anyoneCanPay ? zero : sha256d(concat(tx.inputs.map(outpoint)));
  const hashSequence = anyoneCanPay || single || none ? zero : sha256d(concat(tx.inputs.map((i) => u32le(i.sequence))));
  let hashOutputs = zero;
  if (!single && !none) hashOutputs = sha256d(concat(tx.outputs.map(outputBytes)));
  else if (single && nIn < tx.outputs.length) hashOutputs = sha256d(outputBytes(tx.outputs[nIn]));
  const input = tx.inputs[nIn];
  return sha256d(concat([
    i32le(tx.version), hashPrevouts, hashSequence, outpoint(input), varbytes(scriptCode), i64le(amount),
    u32le(input.sequence), hashOutputs, u32le(tx.locktime), u32le(hashType),
  ]));
}
