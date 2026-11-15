// Build the UNSIGNED kind 10011 event that adds (or refreshes) one BCH claim, ready for a NIP-07 signer.
// Kind 10011 is replaceable: the new event replaces the old one, so every other claim in the current event is carried over.
import { BINDING_KIND, verificationText } from './binding.js';
import { verifyBchMessage } from './bchmsg.js';
import { npubEncode } from './bech32.js';

export function composeBinding({ pubkey, address, proof, current = null, now = Math.floor(Date.now() / 1000) }) {
  if (address !== address.toLowerCase()) throw new Error('address must be the lowercase cashaddr (relay #i lookups match exact strings)');
  const r = verifyBchMessage({ address, message: verificationText(npubEncode(pubkey)), signature: proof });
  if (!r.ok) throw new Error(`proof check failed: ${r.reason}`);
  if (current && current.pubkey !== pubkey) throw new Error('the current event has another author');
  const claim = `bch:${address}`;
  const tags = (current?.tags ?? []).filter((t) => !(t[0] === 'i' && t[1] === claim)).map((t) => [...t]);
  tags.push(['i', claim, proof]);
  return {
    pubkey,
    kind: BINDING_KIND,
    created_at: Math.max(now, (current?.created_at ?? 0) + 1),
    tags,
    content: current?.content ?? '',
  };
}
