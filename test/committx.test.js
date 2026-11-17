// Building and signing a commitment tx from a P2PKH key: every signature checks over the FORKID sighash with the coin's value,
// the commitment reads back with the right signer, the fee pays ≥ 1 sat/byte, change returns to the same address, dust is refused.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { buildCommitmentTx, DUST } from '../src/committx.js';
import { readCommitment, p2pkhScript } from '../src/commit.js';
import { parseTx, txid, sighashForkid } from '../src/bchtx.js';
import { decodeCashaddr } from '../src/cashaddr.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import { BCH_SK, OTHER_SK, NOSTR_SK, nostrPubkey, bchAddress } from './helpers.js';

const PK = nostrPubkey(NOSTR_SK);
const HASH = decodeCashaddr(bchAddress(BCH_SK)).hash;
const coin = (n, value) => ({ txid: bytesToHex(new Uint8Array(32).fill(n)), vout: n, value });

test('signs every input over the FORKID sighash (ALL|FORKID, low-S DER) with that coin\'s value', () => {
  const utxos = [coin(1, 30000n), coin(2, 5000n)];
  const { raw, txid: id } = buildCommitmentTx({ sk: BCH_SK, utxos, pubkey: PK });
  assert.equal(id, txid(raw));
  const tx = parseTx(raw);
  assert.equal(tx.inputs.length, 2);
  tx.inputs.forEach((input, i) => {
    assert.equal(input.prevTxid, utxos[i].txid);
    assert.equal(input.vout, utxos[i].vout);
    const s = input.script;
    assert.equal(s[s[0]], 0x41);
    const sig = s.subarray(1, s[0]);
    const pub = s.subarray(2 + s[0]);
    assert.equal(bytesToHex(pub), bytesToHex(secp256k1.getPublicKey(BCH_SK, true)));
    const digest = sighashForkid(tx, i, p2pkhScript(HASH), utxos[i].value, 0x41);
    assert.ok(secp256k1.verify(sig, digest, pub, { prehash: false, format: 'der', lowS: true }), `input ${i}`);
    assert.ok(!secp256k1.verify(sig, sighashForkid(tx, i, p2pkhScript(HASH), utxos[i].value - 1n, 0x41), pub, { prehash: false, format: 'der' }));
  });
});

test('outputs: the commitment (value 0) then change to the same address; fee ≥ 1 sat per byte and small', () => {
  const utxos = [coin(1, 30000n)];
  const { raw, fee } = buildCommitmentTx({ sk: BCH_SK, utxos, pubkey: PK });
  const tx = parseTx(raw);
  assert.equal(tx.outputs.length, 2);
  assert.equal(tx.outputs[0].value, 0n);
  assert.deepEqual(readCommitment(tx), { pubkey: PK, signerHash: HASH });
  assert.equal(bytesToHex(tx.outputs[1].script), bytesToHex(p2pkhScript(HASH)));
  assert.equal(tx.outputs[1].value, 30000n - fee);
  assert.ok(fee >= BigInt(raw.length), `fee ${fee} < size ${raw.length}`);
  assert.ok(fee <= BigInt(raw.length) + 10n, 'no more than a few sats over 1 sat/byte');
});

test('a revoke commitment builds the same way', () => {
  const { raw } = buildCommitmentTx({ sk: BCH_SK, utxos: [coin(3, 2000n)], pubkey: null });
  assert.equal(readCommitment(parseTx(raw)).pubkey, null);
});

test('refuses dust change, no coins, non-BigInt values and a bad pubkey', () => {
  assert.throws(() => buildCommitmentTx({ sk: BCH_SK, utxos: [coin(1, 700n)], pubkey: PK }), /dust/);
  assert.equal(DUST, 546n);
  assert.throws(() => buildCommitmentTx({ sk: BCH_SK, utxos: [], pubkey: PK }), /coin/);
  assert.throws(() => buildCommitmentTx({ sk: BCH_SK, utxos: [{ ...coin(1, 0n), value: 30000 }], pubkey: PK }), /BigInt/);
  assert.throws(() => buildCommitmentTx({ sk: BCH_SK, utxos: [coin(1, 30000n)], pubkey: 'xyz' }), /pubkey/);
});

test('deterministic (RFC 6979): the same inputs give the same tx; another key gives another signer', () => {
  const a = buildCommitmentTx({ sk: BCH_SK, utxos: [coin(1, 30000n)], pubkey: PK });
  const b = buildCommitmentTx({ sk: BCH_SK, utxos: [coin(1, 30000n)], pubkey: PK });
  assert.equal(a.txid, b.txid);
  const c = buildCommitmentTx({ sk: OTHER_SK, utxos: [coin(1, 30000n)], pubkey: PK });
  assert.notEqual(bytesToHex(readCommitment(parseTx(c.raw)).signerHash), bytesToHex(HASH));
  assert.ok(hexToBytes(a.txid).length === 32);
});
