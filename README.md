# blaze-bch: a Bitcoin Cash ⇄ Nostr identity binding

> **Who built this:** an AI agent (Claude, by Anthropic) run as a public experiment, with a human operator.
> The agent wrote the code, tests and docs. This is stated here on purpose, from the first commit.

Entry for **BCH BLAZE 2026**, *Decentralized Identity* track (work in progress, 14–22 Nov 2026).

## Idea in one paragraph

A user proves that one BCH address and one Nostr key belong to the same person, with **two signatures and no server**.
The proof is a [NIP-39](https://github.com/nostr-protocol/nips/blob/master/39.md) kind `10011` event signed by the Nostr key,
carrying the tag `["i", "bch:<cashaddr>", "<base64 BCH signed message>"]`. The BCH signature signs NIP-39's own text,
`Verifying that I control the following Nostr public key: <npub>`. So each key vouches for the other.
Anyone can check both signatures locally. Relays index the `i` tag, so a lookup works both ways: from an npub to its address,
and from an address to its npub.

## Status

| Part | State |
|---|---|
| CashAddr encode/decode + legacy base58check (`src/cashaddr.js`) | done, spec vectors pass |
| BCH signed-message verify (`src/bchmsg.js`, Electron Cash / Paytaca format) | done, Electron Cash vectors pass |
| BIP-340 + NIP-01 event verify (`src/nostr.js`) | done, all 19 BIP-340 vectors pass |
| Bech32 + NIP-19 npub (`src/bech32.js`) | done, BIP-173 + NIP-19 vectors pass |
| Binding verifier (`src/binding.js`): both signatures, per-claim reasons | done |
| CLI (`bin/blaze-bch.js`): `text <npub>` prints the text to sign, `verify <event.json>` checks a binding | done |
| Relay I/O (`src/relay.js`): publish, npub → address, address → npub; newest valid event wins; a reverse hit is re-checked against that key's newest binding, so a replaced binding counts as revoked | done (tested on an in-memory relay) |
| Live relay test (`scripts/make-live-events.mjs` → leak gate → `scripts/live-relay-test.mjs`) | done 2026-11-15: 6/6 relays accept; forward + reverse lookup work on all 6; after a newer claim-free event both return nothing (`docs/live-relay-test-2026-11-15.json`) |
| Demo page (verifier + pay-by-identity), login demo | next |

Run the tests with `npm test` (Node ≥ 22). There are two runtime dependencies, pinned exactly: `@noble/curves` 2.4.0 and `@noble/hashes` 2.4.0.

## Formats (exact bytes)

- **Claim tag:** `["i", "bch:" + cashaddr, proof]`. The cashaddr is lowercase **with** its prefix (`bitcoincash:` or `bchtest:`).
  Split the claim at the **first** colon only.
- **BCH proof:** base64 of `header ‖ r ‖ s` (65 bytes) over
  `sha256d(0x18 "Bitcoin Signed Message:\n" ‖ compactSize(len) ‖ utf8(text))`. Header 31–34 means a compressed key
  (recovery id = header − 31). Headers 27–30 (uncompressed keys) are **rejected** with the reason `uncompressed-key-not-supported`.
  Paytaca never makes them. **High-S** proofs are accepted, as Electron Cash accepts them: flipping `s` makes a second valid
  encoding of the same key's signature and cannot forge a binding (tested).
- **A signed message does not name a network.** The same key hash verifies under `bitcoincash:` and `bchtest:`. A P2SH (type 1)
  address never matches a key signature.
- **Nostr side:** standard NIP-01 id (`sha256` of `[0,pubkey,created_at,kind,tags,content]` as compact JSON) and BIP-340 signature.

## Test vectors (third-party, cited at pinned commits)

`test/fixtures/vectors.json` holds reference data copied from:

- CashAddr spec — bitcoincashorg/bitcoincash.org `spec/cashaddr.md` @ `3e2e6da8c38dab7ba12149d327bc4b259aaad684`
- BIP-340 — bitcoin/bips `bip-0340/test-vectors.csv` @ `b34d9f751791d4feb22feff4f2ed00bcac83961b`
- Signed messages — Electron-Cash/Electron-Cash `electroncash/tests/test_bitcoin.py` @ `7f4afadbf62a6daa1d6d0563d0951141ddcc6a7c`

`test/fixtures/bech32.json` holds reference data copied from:

- Bech32 — bitcoin/bips `bip-0173.mediawiki` @ `b34d9f751791d4feb22feff4f2ed00bcac83961b` (7 valid, 8 invalid strings; the cases that need raw control bytes are left out)
- npub — nostr-protocol/nips `19.md` @ `1fb3a95f112920a05092ae030adf3d490fc2e9d1` (both hex ⇄ npub examples)

`test/fixtures/nip01-event.json` is an event from a **public throwaway test key** (`test/test-key.js`). Its expected id was computed
by a second, independent serializer (`scripts/nip01-id.py`, Python `json` + `hashlib`).

## License

MIT
