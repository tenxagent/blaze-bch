// Build and sign a commitment tx from ONE P2PKH key: spends the given coins of that key's address, output 0 = the N39B commitment
// (value 0), output 1 = change back to the same address. Signatures: ECDSA, low-S, DER, SIGHASH_ALL|FORKID (0x41), RFC 6979.
// Used for the demo's own commitment; any wallet that can add an OP_RETURN output and spend from one address makes the same bytes.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hash160 } from './bchmsg.js';
import { serializeTx, sighashForkid, txid } from './bchtx.js';
import { commitmentScript, p2pkhScript } from './commit.js';

export const DUST = 546n;
const ALL_FORKID = 0x41;
// Upper bound per input: outpoint 36 + script length 1 + <72-byte low-S DER+type> <33-byte key> = 107 + sequence 4.
const INPUT_MAX = 36 + 1 + 107 + 4;
const outSize = (script) => 8 + 1 + script.length;

// utxos: [{ txid (display hex), vout, value: BigInt sats }], all locked to sk's compressed-key P2PKH address.
export function buildCommitmentTx({ sk, utxos, pubkey, feePerByte = 1n }) {
  if (!Array.isArray(utxos) || utxos.length === 0) throw new Error('committx: no coins to spend');
  if (utxos.length > 252) throw new Error('committx: too many coins');
  if (!utxos.every((u) => typeof u.value === 'bigint' && u.value > 0n)) throw new Error('committx: coin values must be positive BigInt sats');
  const commitment = commitmentScript(pubkey);
  const pub = secp256k1.getPublicKey(sk, true);
  const lock = p2pkhScript(hash160(pub));
  const total = utxos.reduce((s, u) => s + u.value, 0n);
  const maxSize = 10 + utxos.length * INPUT_MAX + outSize(commitment) + outSize(lock);
  const fee = BigInt(maxSize) * BigInt(feePerByte);
  const change = total - fee;
  if (change < DUST) throw new Error(`committx: change ${change} sats would be dust (< ${DUST})`);
  const tx = {
    version: 2,
    inputs: utxos.map((u) => ({ prevTxid: u.txid, vout: u.vout, script: new Uint8Array(), sequence: 0xffffffff })),
    outputs: [{ value: 0n, script: commitment }, { value: change, script: lock }],
    locktime: 0,
  };
  // The FORKID digest does not cover other inputs' unlocking scripts, so each input can be signed against the unsigned tx.
  const sigs = utxos.map((u, i) => {
    const der = secp256k1.sign(sighashForkid(tx, i, lock, u.value, ALL_FORKID), sk, { prehash: false, lowS: true, format: 'der' });
    return Uint8Array.of(der.length + 1, ...der, ALL_FORKID, pub.length, ...pub);
  });
  sigs.forEach((s, i) => { tx.inputs[i].script = s; });
  const raw = serializeTx(tx);
  return { raw, txid: txid(raw), fee, change };
}
