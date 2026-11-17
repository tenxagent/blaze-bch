// Plain-language lines for an address's on-chain state, for the demo page (which only places them, via textContent).
// onchain = lookupOnchain / onchainState result; applied = applyOnchain(keys, onchain); npubOf(pubkey) → npub.
// → [{ text, cls: 'ok' | 'bad' | 'muted' }]
const where = (o) => `block ${o.height}, tx ${o.txid.slice(0, 12)}…`;

export function chainLines(onchain, applied, npubOf) {
  const out = [];
  if (onchain.state === 'none') {
    out.push({ text: 'On chain: no commitment for this address. The relay answer stands.', cls: 'muted' });
  } else if (onchain.state === 'unknown') {
    out.push({ text: `On chain: not checked (${onchain.reason}). The relay answer above is not confirmed by the chain.`, cls: 'muted' });
  } else if (onchain.state === 'revoked') {
    out.push({ text: `✗ On chain: the address's key revoked its link in block ${onchain.height} (tx ${onchain.txid.slice(0, 12)}…). No relay claim of this address counts.`, cls: 'bad' });
  } else if (onchain.state === 'bound') {
    const npub = npubOf(onchain.pubkey);
    if (applied.keys.length) out.push({ text: `✓ On chain: bound to ${npub} (${where(onchain)}).`, cls: 'ok' });
    else out.push({ text: `✗ On chain: bound to ${npub} (${where(onchain)}), but that npub does not claim this address on the relays, so nothing counts.`, cls: 'bad' });
    for (const d of applied.dropped) {
      out.push({ text: `✗ ${d.npub}: the address's key bound it to another npub on chain, so this claim does not count.`, cls: 'bad' });
    }
  }
  const n = (onchain.pending ?? []).length;
  if (n === 1) out.push({ text: '1 unconfirmed commitment is waiting for a block; it counts once confirmed.', cls: 'muted' });
  else if (n > 1) out.push({ text: `${n} unconfirmed commitments are waiting for a block; they count once confirmed.`, cls: 'muted' });
  return out;
}
