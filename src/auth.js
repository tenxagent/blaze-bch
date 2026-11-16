// Challenge-response login with EITHER key, verified locally (spec must 4).
// The app issues a one-time nonce bound to its origin with an expiry. The user answers with
//  - a Nostr kind 27235 event (NIP-98 style) tagged ["u", origin], ["method", "LOGIN"], ["challenge", nonce], or
//  - a BCH signed message over challengeText(challenge).
// Each nonce logs in once. A refusal does not use it up. The app then resolves the other key from relays (src/relay.js).
import { verifyEvent } from './nostr.js';
import { verifyBchMessage } from './bchmsg.js';
import { bytesToHex } from './bytes.js';

export const LOGIN_KIND = 27235;
const MAX_SKEW = 60; // seconds between the event's created_at and the verifier's clock

export function makeChallenge({ origin, now = Math.floor(Date.now() / 1000), ttl = 300 }) {
  return { nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(16))), origin, expires: now + ttl };
}

export const challengeText = (c) =>
  `blaze-bch login\norigin: ${c.origin}\nnonce: ${c.nonce}\nexpires: ${new Date(c.expires * 1000).toISOString()}`;

const tag = (ev, name) => ev.tags.find((t) => t[0] === name)?.[1];

export function createLoginVerifier() {
  const used = new Set();
  const gate = (c, now) => (now > c.expires ? 'expired' : used.has(c.nonce) ? 'replayed' : null);
  return {
    verifyNostr(event, c, now = Math.floor(Date.now() / 1000)) {
      const early = gate(c, now);
      if (early) return { ok: false, reason: early };
      const v = verifyEvent(event);
      if (!v.ok) return v;
      if (event.kind !== LOGIN_KIND) return { ok: false, reason: 'wrong-kind' };
      if (tag(event, 'u') !== c.origin) return { ok: false, reason: 'wrong-origin' };
      if (tag(event, 'challenge') !== c.nonce) return { ok: false, reason: 'wrong-challenge' };
      if (Math.abs(event.created_at - now) > MAX_SKEW) return { ok: false, reason: 'stale-event' };
      used.add(c.nonce);
      return { ok: true, pubkey: event.pubkey };
    },
    verifyBch({ address, signature }, c, now = Math.floor(Date.now() / 1000)) {
      const early = gate(c, now);
      if (early) return { ok: false, reason: early };
      let r;
      try {
        r = verifyBchMessage({ address, message: challengeText(c), signature });
      } catch {
        return { ok: false, reason: 'malformed' };
      }
      if (!r.ok) return r;
      used.add(c.nonce);
      return { ok: true, address: address.toLowerCase() };
    },
  };
}

// Plain-language reasons for the login page. The code stays at the end so a bug report can quote it.
const REFUSALS = {
  expired: 'This challenge has expired. Sign the new text shown above',
  replayed: 'This challenge was already used to log in once. Sign the new text shown above',
  'wrong-origin': 'The signed event names another site, not this one',
  'wrong-challenge': 'The signed event answers a different challenge than the one shown above',
  'wrong-kind': 'The signer returned an event of another kind than a login event',
  'stale-event': 'The event time is more than a minute away from this computer\'s clock',
  malformed: 'The address, signature or event could not be read (expected a CashAddr address and a base64 signature)',
  'bad-id': 'The event was changed after it was signed, so its id does not match',
  'bad-signature': 'The Nostr signature does not check out for this key',
  'address-mismatch': 'The signature was not made by this address\'s key over the text shown above. Check the address; '
    + 'after every login the page shows a new challenge, so a signature from an earlier login no longer fits',
  'recovery-failed': 'No public key could be recovered from this signature',
  'uncompressed-key-not-supported': 'This signature comes from an uncompressed key; only compressed-key (P2PKH) addresses are supported',
};
export const refusalText = (reason) => (REFUSALS[reason] ? `${REFUSALS[reason]} (${reason})` : reason);
