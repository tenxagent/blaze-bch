// BCH Schnorr (the 2019 OP_CHECKSIG Schnorr: e = sha256(r || compressed P || m), Jacobi(R.y) = 1). NOT BIP-340, which Nostr uses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyBchSchnorr } from '../src/bchschnorr.js';
import { parseTx, txid, sighashForkid } from '../src/bchtx.js';
import { hexToBytes } from '../src/bytes.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/bchn-schnorr.json', import.meta.url))).vectors;
const M = JSON.parse(readFileSync(new URL('./fixtures/mainnet-p2pkh-schnorr-spend.json', import.meta.url)));

test('all 13 BCHN Schnorr vectors (5 valid, 8 invalid corner cases)', () => {
  assert.equal(V.length, 13);
  for (const v of V) assert.equal(verifyBchSchnorr(hexToBytes(v.sig), hexToBytes(v.msg), hexToBytes(v.pubkey)), v.valid, v.title);
});

test('flipping any one bit of a valid signature makes it fail', () => {
  const v = V.find((x) => x.valid);
  const sig = hexToBytes(v.sig);
  for (let bit = 0; bit < 512; bit += 37) {
    const bad = Uint8Array.from(sig);
    bad[bit >> 3] ^= 1 << (bit & 7);
    assert.equal(verifyBchSchnorr(bad, hexToBytes(v.msg), hexToBytes(v.pubkey)), false, `bit ${bit}`);
  }
});

test('wrong sizes and an off-curve key are refused, not thrown', () => {
  const v = V.find((x) => x.valid);
  assert.equal(verifyBchSchnorr(hexToBytes(v.sig).subarray(1), hexToBytes(v.msg), hexToBytes(v.pubkey)), false);
  assert.equal(verifyBchSchnorr(hexToBytes(v.sig), hexToBytes(v.msg).subarray(1), hexToBytes(v.pubkey)), false);
  assert.equal(verifyBchSchnorr(hexToBytes(v.sig), hexToBytes(v.msg), Uint8Array.of(2, ...new Uint8Array(32).fill(0xff))), false);
});

test('a REAL mainnet Schnorr P2PKH signature verifies over the FORKID sighash with the real amount, not with 1 sat more', () => {
  assert.equal(txid(hexToBytes(M.raw)), M.txid);
  assert.equal(txid(hexToBytes(M.parentRaw)), M.parentTxid);
  const tx = parseTx(hexToBytes(M.raw));
  const prev = parseTx(hexToBytes(M.parentRaw)).outputs[M.vout];
  const s = tx.inputs[0].script;
  assert.equal(s[0], 65);
  assert.equal(s[65], 0x41);
  const sig = s.subarray(1, 65);
  const pubkey = s.subarray(67);
  const ok = (amount) => verifyBchSchnorr(sig, sighashForkid(tx, 0, prev.script, amount, 0x41), pubkey);
  assert.equal(ok(prev.value), true);
  assert.equal(ok(prev.value + 1n), false);
});
