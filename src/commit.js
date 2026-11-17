// On-chain commitment of a BCH address to a Nostr key (the spec's "BCH transactions as identity commitments" stretch).
//   bind:   OP_RETURN <'N39B'> <32-byte x-only Nostr pubkey>
//   revoke: OP_RETURN <'N39B'> <empty push>
// The committing address is the P2PKH key that spends input 0 (unlocking script = <signature> <pubkey>). One commitment output per tx.
// For an address, the newest CONFIRMED commitment wins, so a later tx replaces or revokes an earlier one, in block order, for everyone.
// Signatures are not re-checked here: every BCH node checked them before the tx was mined. What this code checks: the bytes hash to
// the txid the server named (a server cannot swap content), the commitment's exact shape, and who spent input 0.
// A server CAN hide a tx or lie about its height ⇒ callers ask more than one server (see the README, Trust and limits).
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeCashaddr } from './cashaddr.js';
import { hash160 } from './bchmsg.js';
import { txid as txidOf, parseTx } from './bchtx.js';
import { bytesToHex, hexToBytes } from './bytes.js';

export const COMMIT_PREFIX = 'N39B';
const PREFIX = new TextEncoder().encode(COMMIT_PREFIX);
const OP_RETURN = 0x6a;
const PUBKEY = /^[0-9a-f]{64}$/;

export function commitmentScript(pubkey) {
  if (pubkey === null) return Uint8Array.of(OP_RETURN, 4, ...PREFIX, 0x00);
  if (typeof pubkey !== 'string' || !PUBKEY.test(pubkey)) throw new Error('commit: pubkey must be 64 lowercase hex');
  return Uint8Array.of(OP_RETURN, 4, ...PREFIX, 32, ...hexToBytes(pubkey));
}

const isOurs = (s) => s.length >= 6 && s[0] === OP_RETURN && s[1] === 4 && PREFIX.every((b, i) => s[2 + i] === b);

// Parses the commitment payload after the prefix: exactly one push of 32 bytes (bind) or of 0 bytes (revoke), nothing after it.
function payload(s) {
  const rest = s.subarray(6);
  if (rest.length === 1 && rest[0] === 0x00) return null;
  if (rest.length === 33 && rest[0] === 32) return bytesToHex(rest.subarray(1));
  throw new Error('commit: malformed commitment output');
}

// Input 0 must be a plain P2PKH spend: two direct pushes, a signature (65 Schnorr or 9..73 DER+type) and a 33/65-byte pubkey.
function signerHash(script) {
  const sigLen = script[0];
  if (!(sigLen >= 9 && sigLen <= 75) || script.length < 1 + sigLen + 1) throw new Error('commit: input 0 is not a P2PKH spend');
  const pkLen = script[1 + sigLen];
  const pk = script.subarray(2 + sigLen);
  const okKey = (pkLen === 33 && (pk[0] === 2 || pk[0] === 3)) || (pkLen === 65 && pk[0] === 4);
  if (!okKey || pk.length !== pkLen) throw new Error('commit: input 0 is not a P2PKH spend');
  return hash160(pk);
}

// → null (no N39B output) | { pubkey: hex | null (revoke), signerHash: 20 bytes }
export function readCommitment(tx) {
  const ours = tx.outputs.filter((o) => isOurs(o.script));
  if (ours.length === 0) return null;
  if (ours.length > 1) throw new Error('commit: more than one commitment output');
  const pubkey = payload(ours[0].script);
  return { pubkey, signerHash: signerHash(tx.inputs[0].script) };
}

const p2pkhHash = (address) => {
  const { type, hash } = decodeCashaddr(address);
  if (type !== 0 || hash.length !== 20) throw new Error('commit: only P2PKH cashaddrs can commit');
  return hash;
};

export const p2pkhScript = (hash) => Uint8Array.of(0x76, 0xa9, 20, ...hash, 0x88, 0xac);

// Electrum/Fulcrum address key: sha256 of the locking script, byte-reversed, hex.
export const scripthash = (address) => bytesToHex(sha256(p2pkhScript(p2pkhHash(address))).reverse());

// entries: [{ txid, raw (bytes), height }] for the address's history (height ≤ 0 = unconfirmed). Every entry is hashed and must match
// its txid. → { state: 'none' | 'bound' | 'revoked', pubkey?, txid?, height?, pending: [unconfirmed commitments of this address] }
export function onchainState(address, entries) {
  const want = bytesToHex(p2pkhHash(address));
  const mine = [];
  for (const e of entries) {
    if (txidOf(e.raw) !== e.txid) throw new Error(`commit: bytes do not hash to txid ${e.txid}`);
    const c = readCommitment(parseTx(e.raw));
    if (c && bytesToHex(c.signerHash) === want) mine.push({ txid: e.txid, height: e.height, pubkey: c.pubkey });
  }
  const confirmed = mine.filter((m) => m.height > 0);
  const pending = mine.filter((m) => !(m.height > 0));
  if (!confirmed.length) return { state: 'none', pending };
  // Newest = highest block; within one block, the later entry in the list (Electrum history lists a block's txs in block order).
  const newest = confirmed.reduce((best, m) => (m.height >= best.height ? m : best));
  return { state: newest.pubkey === null ? 'revoked' : 'bound', pubkey: newest.pubkey, txid: newest.txid, height: newest.height, pending };
}
