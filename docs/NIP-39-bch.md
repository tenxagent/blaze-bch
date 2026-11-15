# NIP-39 claim type `bch`: Bitcoin Cash address

`draft` `optional`

This extends [NIP-39](https://github.com/nostr-protocol/nips/blob/master/39.md) (external identities in kind `10011` events) with one
claim type for Bitcoin Cash. Unlike the web2 claim types, the proof is **inline**: verifying it needs no URL, no fetch and no server.

## Tag

```json
["i", "bch:<cashaddr>", "<proof>"]
```

- `<cashaddr>`: a P2PKH CashAddr, lowercase, **with** its prefix (`bitcoincash:` on mainnet, `bchtest:` on testnet/chipnet).
  The claim value is therefore `bch:bitcoincash:q…`. Parse it by splitting at the **first** `:`.
- `<proof>`: a Bitcoin Cash signed message, in base64, by the address's key over NIP-39's verification text:

  ```
  Verifying that I control the following Nostr public key: <npub>
  ```

  `<npub>` is the NIP-19 encoding of the event's `pubkey`.

## Proof format

The signed digest is `sha256(sha256(0x18 ‖ "Bitcoin Signed Message:\n" ‖ compactSize(len) ‖ utf8(text)))`, which is what Electron Cash
and Paytaca produce with *Sign message*. The proof is `base64(header ‖ r ‖ s)`, 65 bytes:

- `header` 31–34: compressed public key, recovery id = `header − 31`. Accept these.
- `header` 27–30 (uncompressed keys): reject with a clear reason. Wallets in use today do not make them.
- A high-S `s` is accepted. Flipping `s` gives a second encoding of the same signature and cannot forge a claim.

## Verification

An address counts as bound to the event's pubkey only when **both** of these hold:

1. The event is valid (NIP-01 id + BIP-340 signature). This shows the Nostr key published the claim.
2. Recovering the public key from `<proof>` over the verification text for **this event's** npub gives a key whose `hash160` equals the address's
   payload, and the address type is P2PKH. This shows the BCH key named this npub.

A proof copied into another key's event fails check 2: it names the original npub, not the copier's.

A signed message does not commit to a network, so the same key verifies under `bitcoincash:` and `bchtest:`. The prefix only says which network
the user means.

## Discovery

- **npub → address:** `{"kinds": [10011], "authors": [<pubkey>]}`. Use the newest valid event (`created_at`, then the lowest `id`), read from
  several relays so that one stale relay cannot roll a user back.
- **address → npub:** `{"kinds": [10011], "#i": ["bch:<cashaddr>"]}`. This works because single-letter tags are indexed and the claim value is exact
  (lowercase, prefixed). For each hit, fetch that author's newest kind `10011` and keep the hit only if that event **still** proves the address.

## Revocation

Kind `10011` is replaceable. Publishing a newer `10011` without the claim revokes it, and the reverse-lookup rule above honours that.
Relays that never received the newer event can still serve the old one, so read from several relays.

## Reference implementation

This repository: `src/binding.js` (verify), `src/relay.js` (discovery + revocation), `src/compose.js` (keep the user's other claims when
adding one), with test vectors from the CashAddr spec, BIP-340 and Electron Cash. On 2026-11-15, publish, both lookups and revocation passed on
six public relays (`docs/live-relay-test-2026-11-15.json`).
