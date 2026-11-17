// On-chain commitment: OP_RETURN 'N39B' <32-byte Nostr pubkey> (an empty push = revoke), made by the P2PKH key of input 0.
// The newest CONFIRMED commitment of an address wins. A server could invent a tx, so the verifier checks input 0's signature itself
// against the parent output it spends (parent bytes must hash to the outpoint's txid), and the signature must cover all outputs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { COMMIT_PREFIX, commitmentScript, readCommitment, onchainState, p2pkhScript, scripthash } from '../src/commit.js';
import { buildCommitmentTx } from '../src/committx.js';
import { parseTx, serializeTx, txid, sighashForkid } from '../src/bchtx.js';
import { decodeCashaddr, encodeCashaddr } from '../src/cashaddr.js';
import { hash160 } from '../src/bchmsg.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import { BCH_SK, OTHER_SK, NOSTR_SK, nostrPubkey, bchAddress } from './helpers.js';

const PK = nostrPubkey(NOSTR_SK);
const PK2 = nostrPubkey(OTHER_SK);
const ADDR = bchAddress(BCH_SK);
const hashOf = (sk) => hash160(secp256k1.getPublicKey(sk, true));
const push = (b) => Uint8Array.of(b.length, ...b);
// Shape-only txs for readCommitment: <placeholder signature> <pubkey>. readCommitment reads shapes; onchainState checks signatures.
const unlock = (sk) => Uint8Array.of(...push(new Uint8Array(71).fill(0x30)), ...push(secp256k1.getPublicKey(sk, true)));
let seq = 0;
const tx = (sk, ...scripts) => serializeTx({
  version: 2,
  inputs: [{ prevTxid: bytesToHex(new Uint8Array(32).fill(++seq)), vout: 0, script: unlock(sk), sequence: 0xffffffff }],
  outputs: [...scripts.map((s) => ({ value: 0n, script: s })), { value: 1000n, script: p2pkhScript(decodeCashaddr(ADDR).hash) }],
  locktime: 0,
});
// Really signed commitment txs: a parent pays sk's address, the commitment tx spends it (buildCommitmentTx).
const signed = (sk, pubkey, value = 30000n) => {
  const parentRaw = serializeTx({
    version: 2,
    inputs: [{ prevTxid: bytesToHex(new Uint8Array(32).fill(++seq)), vout: 7, script: Uint8Array.of(0x51), sequence: 0xffffffff }],
    outputs: [{ value: 1n, script: Uint8Array.of(0x51) }, { value, script: p2pkhScript(hashOf(sk)) }],
    locktime: 0,
  });
  const { raw } = buildCommitmentTx({ sk, utxos: [{ txid: txid(parentRaw), vout: 1, value }], pubkey });
  return { raw, parentRaw };
};
const entry = ({ raw, parentRaw }, height) => ({ txid: txid(raw), raw, parentRaw, height });

test('commitment script bytes: OP_RETURN, push 4 "N39B", push 32 pubkey; revoke = push 0', () => {
  assert.equal(COMMIT_PREFIX, 'N39B');
  assert.equal(bytesToHex(commitmentScript(PK)), `6a04${bytesToHex(new TextEncoder().encode('N39B'))}20${PK}`);
  assert.equal(bytesToHex(commitmentScript(null)), '6a044e33394200');
  assert.throws(() => commitmentScript('ab'), /pubkey/);
  assert.throws(() => commitmentScript(PK.toUpperCase()), /pubkey/);
});

test('readCommitment: finds the pubkey and the input-0 signer, ignores txs without one', () => {
  const c = readCommitment(parseTx(tx(BCH_SK, commitmentScript(PK))));
  assert.equal(c.pubkey, PK);
  assert.equal(bytesToHex(c.signerHash), bytesToHex(decodeCashaddr(ADDR).hash));
  assert.equal(readCommitment(parseTx(tx(BCH_SK, commitmentScript(null)))).pubkey, null);
  assert.equal(readCommitment(parseTx(tx(BCH_SK, Uint8Array.of(0x6a, 4, 1, 2, 3, 4)))), null, 'other OP_RETURN protocols');
  assert.equal(readCommitment(parseTx(tx(BCH_SK))), null, 'no OP_RETURN at all');
});

test('readCommitment refuses ambiguous or malformed commitments', () => {
  assert.throws(() => readCommitment(parseTx(tx(BCH_SK, commitmentScript(PK), commitmentScript(PK2)))), /more than one/);
  const short = Uint8Array.of(0x6a, 4, ...new TextEncoder().encode('N39B'), 31, ...new Uint8Array(31));
  assert.throws(() => readCommitment(parseTx(tx(BCH_SK, short))), /malformed/);
  const extra = Uint8Array.of(...commitmentScript(PK), 1, 0);
  assert.throws(() => readCommitment(parseTx(tx(BCH_SK, extra))), /malformed/);
  const notP2pkh = parseTx(tx(BCH_SK, commitmentScript(PK)));
  notP2pkh.inputs[0].script = Uint8Array.of(0x00, 0x51); // not <sig> <pubkey>
  assert.throws(() => readCommitment(notP2pkh), /P2PKH/);
});

test('onchainState: newest confirmed commitment of THIS address wins; unconfirmed ones are only reported', () => {
  const a = signed(BCH_SK, PK);
  const b = signed(BCH_SK, PK2);
  const r = signed(BCH_SK, null);
  const theirs = signed(OTHER_SK, PK2); // someone else's address committing: not ours, ignored
  assert.deepEqual(onchainState(ADDR, []), { state: 'none', pending: [] });
  let s = onchainState(ADDR, [entry(a, 100)]);
  assert.equal(s.state, 'bound');
  assert.equal(s.pubkey, PK);
  assert.equal(s.height, 100);
  assert.equal(s.txid, txid(a.raw));
  s = onchainState(ADDR, [entry(a, 100), entry(theirs, 101), entry(b, 102)]);
  assert.equal(s.pubkey, PK2);
  s = onchainState(ADDR, [entry(b, 102), entry(a, 100)]); // order of the list does not matter across heights
  assert.equal(s.pubkey, PK2);
  s = onchainState(ADDR, [entry(a, 100), entry(r, 101)]);
  assert.equal(s.state, 'revoked');
  assert.equal(s.pubkey, null);
  s = onchainState(ADDR, [entry(a, 100), entry(r, 0)]); // the revocation is still in the mempool
  assert.equal(s.state, 'bound');
  assert.equal(s.pending.length, 1);
  assert.equal(s.pending[0].pubkey, null);
});

test('onchainState: a newer commitment by ANOTHER key in the history does not count', () => {
  const a = signed(BCH_SK, PK);
  const theirs = signed(OTHER_SK, null); // e.g. a tx that paid this address and carries a revoke of its own
  const s = onchainState(ADDR, [entry(a, 100), entry(theirs, 105)]);
  assert.equal(s.state, 'bound');
  assert.equal(s.pubkey, PK);
  assert.equal(s.txid, txid(a.raw));
});

test('onchainState: unconfirmed alone is "none" (height 0 and -1 are mempool), and same-block ties go to the later entry', () => {
  const a = signed(BCH_SK, PK);
  const b = signed(BCH_SK, PK2);
  for (const h of [0, -1]) {
    const s = onchainState(ADDR, [entry(a, h)]);
    assert.equal(s.state, 'none');
    assert.equal(s.pending.length, 1);
  }
  assert.equal(onchainState(ADDR, [entry(a, 100), entry(b, 100)]).pubkey, PK2);
  assert.equal(onchainState(ADDR, [entry(b, 100), entry(a, 100)]).pubkey, PK);
});

test('onchainState refuses bytes that are not the claimed txid (a server cannot swap the content)', () => {
  const a = signed(BCH_SK, PK);
  const b = signed(BCH_SK, PK2);
  assert.throws(() => onchainState(ADDR, [{ ...entry(a, 100), raw: b.raw }]), /txid/);
});

test('onchainState refuses an invented tx: placeholder signature, wrong parent, or a signature that does not cover the outputs', () => {
  const a = signed(BCH_SK, PK);
  const forged = { raw: tx(BCH_SK, commitmentScript(null)), parentRaw: a.parentRaw }; // right shape, no real signature
  assert.throws(() => onchainState(ADDR, [entry(a, 100), entry(forged, 101)]), /signature|parent/);
  const wrongParent = { raw: a.raw, parentRaw: signed(BCH_SK, PK).parentRaw };
  assert.throws(() => onchainState(ADDR, [entry(wrongParent, 100)]), /parent/);
  assert.throws(() => onchainState(ADDR, [{ ...entry(a, 100), parentRaw: undefined }]), /parent/);
  // Re-sign input 0 with SIGHASH_NONE|FORKID: a valid signature that does NOT cover the outputs, so anyone could add a commitment.
  const t = parseTx(hexToBytes(bytesToHex(a.raw)));
  const parentOut = parseTx(a.parentRaw).outputs[1];
  const der = secp256k1.sign(sighashForkid(t, 0, parentOut.script, parentOut.value, 0x42), BCH_SK, { prehash: false, lowS: true, format: 'der' });
  const pub = secp256k1.getPublicKey(BCH_SK, true);
  t.inputs[0].script = Uint8Array.of(der.length + 1, ...der, 0x42, 33, ...pub);
  const none = { raw: serializeTx(t), parentRaw: a.parentRaw };
  assert.throws(() => onchainState(ADDR, [entry(none, 100)]), /cover/);
});

test('onchainState refuses a right-parent spend whose signature is over another digest (here: signed for 1 sat less)', () => {
  const a = signed(BCH_SK, PK);
  const t = parseTx(hexToBytes(bytesToHex(a.raw)));
  const parentOut = parseTx(a.parentRaw).outputs[1];
  const der = secp256k1.sign(sighashForkid(t, 0, parentOut.script, parentOut.value - 1n, 0x41), BCH_SK, { prehash: false, lowS: true, format: 'der' });
  t.inputs[0].script = Uint8Array.of(der.length + 1, ...der, 0x41, 33, ...secp256k1.getPublicKey(BCH_SK, true));
  assert.throws(() => onchainState(ADDR, [entry({ raw: serializeTx(t), parentRaw: a.parentRaw }, 100)]), /signature does not check out/);
});

test('onchainState refuses a valid signature over a parent output that is not this key\'s P2PKH lock', () => {
  // The parent output is OP_TRUE (anyone can spend); the key signs over THAT script. The signature checks, the coin was never the address's.
  const parentRaw = serializeTx({
    version: 2,
    inputs: [{ prevTxid: bytesToHex(new Uint8Array(32).fill(++seq)), vout: 0, script: Uint8Array.of(0x51), sequence: 0xffffffff }],
    outputs: [{ value: 30000n, script: Uint8Array.of(0x51) }],
    locktime: 0,
  });
  const t = {
    version: 2,
    inputs: [{ prevTxid: txid(parentRaw), vout: 0, script: new Uint8Array(), sequence: 0xffffffff }],
    outputs: [{ value: 0n, script: commitmentScript(null) }, { value: 29000n, script: p2pkhScript(hashOf(BCH_SK)) }],
    locktime: 0,
  };
  const der = secp256k1.sign(sighashForkid(t, 0, Uint8Array.of(0x51), 30000n, 0x41), BCH_SK, { prehash: false, lowS: true, format: 'der' });
  t.inputs[0].script = Uint8Array.of(der.length + 1, ...der, 0x41, 33, ...secp256k1.getPublicKey(BCH_SK, true));
  assert.throws(() => onchainState(ADDR, [entry({ raw: serializeTx(t), parentRaw }, 100)]), /P2PKH lock/);
});

// Test-only BCH Schnorr signer (spec 2019-05-15): k from the key and message, R.y made a quadratic residue, s = k + e·x mod n.
// verifyBchSchnorr itself is pinned to BCHN's vectors and a mainnet signature (test/bchschnorr.test.js).
function schnorrSignBch(digest, sk) {
  const { Point } = secp256k1;
  const n = Point.Fn.ORDER;
  const p = Point.Fp.ORDER;
  const num = (b) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
  const be32 = (x) => hexToBytes(x.toString(16).padStart(64, '0'));
  const x = num(sk);
  let k = num(sha256(Uint8Array.of(...sk, ...digest))) % n;
  const R = Point.BASE.multiply(k).toAffine();
  if (Point.Fp.pow(R.y, (p - 1n) / 2n) !== 1n) k = n - k;
  const r = be32(R.x);
  const e = num(sha256(Uint8Array.of(...r, ...secp256k1.getPublicKey(sk, true), ...digest))) % n;
  return Uint8Array.of(...r, ...be32((k + e * x) % n));
}

test('onchainState checks a BCH Schnorr (65-byte) input 0 too: right digest accepted, wrong digest refused', () => {
  const a = signed(BCH_SK, PK);
  const parentOut = parseTx(a.parentRaw).outputs[1];
  const withSchnorr = (amount) => {
    const t = parseTx(hexToBytes(bytesToHex(a.raw)));
    const sig = schnorrSignBch(sighashForkid(t, 0, parentOut.script, amount, 0x41), BCH_SK);
    t.inputs[0].script = Uint8Array.of(65, ...sig, 0x41, 33, ...secp256k1.getPublicKey(BCH_SK, true));
    return { raw: serializeTx(t), parentRaw: a.parentRaw };
  };
  assert.equal(onchainState(ADDR, [entry(withSchnorr(parentOut.value), 100)]).pubkey, PK);
  assert.throws(() => onchainState(ADDR, [entry(withSchnorr(parentOut.value - 1n), 100)]), /signature does not check out/);
});

test('onchainState skips history txs that are not valid commitments (anyone can send junk to an address), not the lookup', () => {
  const a = signed(BCH_SK, PK);
  const junk2 = tx(OTHER_SK, commitmentScript(PK2), commitmentScript(null)); // two commitment outputs
  const notP2pkh = parseTx(tx(OTHER_SK, commitmentScript(null)));
  notP2pkh.inputs[0].script = Uint8Array.of(0x00, 0x51);
  const junk3 = serializeTx(notP2pkh);
  const junkEntry = (raw, h) => ({ txid: txid(raw), raw, height: h });
  const s = onchainState(ADDR, [entry(a, 100), junkEntry(junk2, 105), junkEntry(junk3, 106)]);
  assert.equal(s.state, 'bound');
  assert.equal(s.pubkey, PK);
});

test('onchainState only takes P2PKH cashaddrs', () => {
  const p2sh = encodeCashaddr('bitcoincash', 1, hash160(new Uint8Array(1)));
  assert.throws(() => onchainState(p2sh, []), /P2PKH/);
});

test('p2pkhScript + Electrum scripthash match the Electrum protocol docs example (address of the genesis coinbase key)', () => {
  const h = hexToBytes('62e907b15cbf27d5425399ebf6f0fb50ebb88f18');
  assert.equal(bytesToHex(p2pkhScript(h)), '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac');
  assert.equal(scripthash(encodeCashaddr('bitcoincash', 0, h)), '8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161');
});
