// BCH <-> Nostr binding check for a NIP-39 kind 10011 event.
// The Nostr key signs the event (NIP-01 / BIP-340); each ["i", "bch:<cashaddr>", "<proof>"] tag carries a BCH signed message
// over NIP-39's verification text naming this event's npub. Both signatures must hold for an address to count as bound.
import { verifyEvent } from './nostr.js';
import { verifyBchMessage } from './bchmsg.js';
import { parseClaim } from './cashaddr.js';
import { npubEncode } from './bech32.js';

export const BINDING_KIND = 10011;

export const verificationText = (npub) => `Verifying that I control the following Nostr public key: ${npub}`;

function checkClaim(tag, text) {
  let claim;
  try {
    claim = parseClaim(tag[1]);
  } catch {
    return null; // not a well-formed NIP-39 claim at all: not ours to judge
  }
  if (claim.platform !== 'bch') return null;
  const address = claim.identity;
  if (address !== address.toLowerCase()) return { address, reason: 'non-canonical-address' };
  if (typeof tag[2] !== 'string') return { address, reason: 'malformed-claim' };
  try {
    const r = verifyBchMessage({ address, message: text, signature: tag[2] });
    return r.ok ? { address, ok: true } : { address, reason: r.reason };
  } catch {
    return { address, reason: 'malformed-claim' };
  }
}

// Returns { ok: false, reason } when the event itself is unusable, else
// { ok: true, pubkey, npub, verified: [cashaddr...], rejected: [{ address, reason }...] }.
export function verifyBinding(event) {
  const ev = verifyEvent(event);
  if (!ev.ok) return ev;
  if (event.kind !== BINDING_KIND) return { ok: false, reason: 'wrong-kind' };
  const npub = npubEncode(event.pubkey);
  const text = verificationText(npub);
  const verified = [];
  const rejected = [];
  for (const tag of event.tags) {
    if (tag[0] !== 'i') continue;
    const r = checkClaim(tag, text);
    if (!r) continue;
    if (r.ok) verified.push(r.address);
    else rejected.push({ address: r.address, reason: r.reason });
  }
  return { ok: true, pubkey: event.pubkey, npub, verified, rejected };
}
