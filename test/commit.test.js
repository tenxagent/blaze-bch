// On-chain commitment: OP_RETURN 'N39B' <32-byte Nostr pubkey> (an empty push = revoke), made by the P2PKH key of input 0.
// The newest CONFIRMED commitment of an address wins. Signatures are not re-checked here: a confirmed tx was already checked by
// every BCH node; what this code checks is that the bytes really are that txid and who spent input 0.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { COMMIT_PREFIX, commitmentScript, readCommitment, onchainState, p2pkhScript, scripthash } from '../src/commit.js';
import { parseTx, serializeTx, txid } from '../src/bchtx.js';
import { decodeCashaddr, encodeCashaddr } from '../src/cashaddr.js';
import { hash160 } from '../src/bchmsg.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import { BCH_SK, OTHER_SK, NOSTR_SK, nostrPubkey, bchAddress } from './helpers.js';

const PK = nostrPubkey(NOSTR_SK);
const PK2 = nostrPubkey(OTHER_SK);
const ADDR = bchAddress(BCH_SK);
const push = (b) => Uint8Array.of(b.length, ...b);
// A P2PKH unlocking script shape: <signature> <pubkey>. The signature bytes are a placeholder: nodes check them, this code does not.
const unlock = (sk) => Uint8Array.of(...push(new Uint8Array(71).fill(0x30)), ...push(secp256k1.getPublicKey(sk, true)));
let seq = 0;
const tx = (sk, ...scripts) => serializeTx({
  version: 2,
  inputs: [{ prevTxid: bytesToHex(new Uint8Array(32).fill(++seq)), vout: 0, script: unlock(sk), sequence: 0xffffffff }],
  outputs: [...scripts.map((s) => ({ value: 0n, script: s })), { value: 1000n, script: p2pkhScript(decodeCashaddr(ADDR).hash) }],
  locktime: 0,
});
const entry = (raw, height) => ({ txid: txid(raw), raw, height });

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
  const a = tx(BCH_SK, commitmentScript(PK));
  const b = tx(BCH_SK, commitmentScript(PK2));
  const r = tx(BCH_SK, commitmentScript(null));
  const theirs = tx(OTHER_SK, commitmentScript(PK2)); // someone else's address committing: not ours, ignored
  assert.deepEqual(onchainState(ADDR, []), { state: 'none', pending: [] });
  let s = onchainState(ADDR, [entry(a, 100)]);
  assert.equal(s.state, 'bound');
  assert.equal(s.pubkey, PK);
  assert.equal(s.height, 100);
  assert.equal(s.txid, txid(a));
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
  const a = tx(BCH_SK, commitmentScript(PK));
  const theirs = tx(OTHER_SK, commitmentScript(null)); // e.g. a tx that paid this address and carries a revoke of its own
  const s = onchainState(ADDR, [entry(a, 100), entry(theirs, 105)]);
  assert.equal(s.state, 'bound');
  assert.equal(s.pubkey, PK);
  assert.equal(s.txid, txid(a));
});

test('onchainState: unconfirmed alone is "none" (height 0 and -1 are mempool), and same-block ties go to the later entry', () => {
  const a = tx(BCH_SK, commitmentScript(PK));
  const b = tx(BCH_SK, commitmentScript(PK2));
  for (const h of [0, -1]) {
    const s = onchainState(ADDR, [entry(a, h)]);
    assert.equal(s.state, 'none');
    assert.equal(s.pending.length, 1);
  }
  assert.equal(onchainState(ADDR, [entry(a, 100), entry(b, 100)]).pubkey, PK2);
  assert.equal(onchainState(ADDR, [entry(b, 100), entry(a, 100)]).pubkey, PK);
});

test('onchainState refuses bytes that are not the claimed txid (a server cannot swap the content)', () => {
  const a = tx(BCH_SK, commitmentScript(PK));
  const b = tx(BCH_SK, commitmentScript(PK2));
  assert.throws(() => onchainState(ADDR, [{ txid: txid(a), raw: b, height: 100 }]), /txid/);
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
