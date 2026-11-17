// Pay by identity: npub -> the address its CURRENT binding proves -> a BCH payment URI (cashaddr + BIP21-style query).
import { decodeCashaddr, encodeCashaddr } from './cashaddr.js';
import { npubDecode } from './bech32.js';
import { lookupByPubkey } from './relay.js';
import { applyOnchain } from './commit.js';

const AMOUNT = /^\d+(\.\d{1,8})?$/;

function normalizeAmount(amount) {
  const s = typeof amount === 'number' ? String(amount) : amount;
  if (typeof s !== 'string' || !AMOUNT.test(s)) throw new Error('amount: expected a positive BCH number with at most 8 decimals');
  const [int, frac = ''] = s.split('.');
  const clean = frac.replace(/0+$/, '') ? `${BigInt(int)}.${frac.replace(/0+$/, '')}` : `${BigInt(int)}`;
  if (/^0(\.0*)?$/.test(clean)) throw new Error('amount: must be more than zero');
  return clean;
}

export function paymentUri(address, { amount, label } = {}) {
  const { prefix, type, hash } = decodeCashaddr(address);
  const uri = encodeCashaddr(prefix, type, hash);
  const q = [];
  if (amount !== undefined) q.push(`amount=${normalizeAmount(amount)}`);
  if (label) q.push(`label=${encodeURIComponent(label)}`);
  return q.length ? `${uri}?${q.join('&')}` : uri;
}

// Returns { address, uri } or null when the npub has no current verified BCH binding on these relays.
// opts.onchain (optional): async (address) => on-chain state (fulcrum.js lookupOnchain). With it, the address must also pass the chain
// (commit.js applyOnchain): revoked or bound to another key ⇒ uri null + reason; unknown ⇒ the uri, checked false + reason.
export async function resolvePayment(npub, urls, opts = {}) {
  const { amount, label, onchain, ...relayOpts } = opts;
  const pubkey = npubDecode(npub);
  const found = await lookupByPubkey(pubkey, urls, relayOpts);
  const address = found?.verified?.[0];
  if (!address) return null;
  const uri = paymentUri(address, { amount, label });
  if (!onchain) return { address, uri };
  const r = applyOnchain([{ pubkey }], await onchain(address));
  if (!r.keys.length) return { address, uri: null, checked: true, reason: r.dropped[0].reason };
  return r.checked ? { address, uri, checked: true } : { address, uri, checked: false, reason: r.reason };
}
