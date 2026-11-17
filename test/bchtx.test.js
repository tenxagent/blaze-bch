// BCH transaction bytes: parse/serialize round-trip, txid, and the FORKID signature hash pinned to Bitcoin Cash Node's own vectors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseTx, serializeTx, txid, sighashForkid } from '../src/bchtx.js';
import { hexToBytes, bytesToHex } from '../src/bytes.js';

const F = JSON.parse(readFileSync(new URL('./fixtures/bchn-sighash-forkid.json', import.meta.url)));
const reversedHex = (u8) => bytesToHex(Uint8Array.from(u8).reverse());

test('the fixture holds the 494 FORKID rows', () => {
  assert.equal(F.rows.length, 494);
  assert.ok(F.rows.every((r) => r[3] & 0x40));
});

test('every vector tx parses and serializes back to the same bytes', () => {
  for (const [raw] of F.rows) assert.equal(bytesToHex(serializeTx(parseTx(hexToBytes(raw)))), raw);
});

test('parse reads the fields in order (first vector by hand)', () => {
  const tx = parseTx(hexToBytes(F.rows[0][0]));
  const raw = F.rows[0][0];
  assert.equal(tx.version, new DataView(hexToBytes(raw.slice(0, 8)).buffer).getInt32(0, true));
  assert.equal(tx.locktime, new DataView(hexToBytes(raw.slice(-8)).buffer).getUint32(0, true));
  assert.ok(tx.inputs.length > 0 && tx.outputs.length > 0);
  for (const i of tx.inputs) assert.equal(i.prevTxid.length, 64);
  for (const o of tx.outputs) assert.equal(typeof o.value, 'bigint');
});

test('trailing or missing bytes are refused', () => {
  const raw = hexToBytes(F.rows[0][0]);
  assert.throws(() => parseTx(Uint8Array.of(...raw, 0)), /trailing/);
  assert.throws(() => parseTx(raw.subarray(0, raw.length - 1)), /short/);
});

test('txid = byte-reversed sha256d of the raw tx (display order)', () => {
  // A known mainnet tx: the BCH genesis coinbase is shared with BTC; its txid is famous.
  const genesisCoinbase = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';
  assert.equal(txid(hexToBytes(genesisCoinbase)), '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b');
});

test('sighashForkid matches all 494 BCHN FORKID rows (input value 0, as in their harness)', () => {
  let n = 0;
  for (const [raw, script, nIn, hashType, expected] of F.rows) {
    const got = sighashForkid(parseTx(hexToBytes(raw)), nIn, hexToBytes(script), 0n, hashType);
    assert.equal(reversedHex(got), expected, `row ${n}`);
    n++;
  }
  assert.equal(n, 494);
});

test('sighashForkid refuses a hash type without the FORKID bit and an input index out of range', () => {
  const tx = parseTx(hexToBytes(F.rows[0][0]));
  assert.throws(() => sighashForkid(tx, 0, new Uint8Array(), 0n, 0x01), /FORKID/);
  assert.throws(() => sighashForkid(tx, tx.inputs.length, new Uint8Array(), 0n, 0x41), /input/);
});
