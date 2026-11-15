// Pay by identity: npub -> the address its CURRENT binding proves -> a BCH payment URI (cashaddr + BIP21-style query).
import { decodeCashaddr, encodeCashaddr } from './cashaddr.js';
import { npubDecode } from './bech32.js';
import { lookupByPubkey } from './relay.js';

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
export async function resolvePayment(npub, urls, opts = {}) {
  const { amount, label, ...relayOpts } = opts;
  const found = await lookupByPubkey(npubDecode(npub), urls, relayOpts);
  const address = found?.verified?.[0];
  return address ? { address, uri: paymentUri(address, { amount, label }) } : null;
}
