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

## How it works

**Linking (once per address).**

1. The user's Nostr signer (NIP-07) gives the page the npub.
2. The user signs `Verifying that I control the following Nostr public key: <npub>` in any BCH wallet, using *Sign message*.
3. The page builds a kind `10011` event. It keeps every claim the user already has (GitHub, X…) and adds `["i", "bch:<address>", <signature>]`.
4. The Nostr signer signs the event, and the page publishes it to several relays.

**Checking (anyone, any time, offline once the event is fetched).**

1. The event's id and BIP-340 signature must be valid, which shows the Nostr key published it.
2. For each `bch:` claim, recover the public key from the BCH signature over the text **with this event's npub**. Its `hash160` must equal the
   address payload, which shows the BCH key named this npub.
3. A proof copied into someone else's event fails step 2, because it names the original npub.

**Discovery.**

- **npub → address:** read the author's kind `10011` from several relays and keep the newest valid one.
- **address → npub:** relays index the claim tag (`#i`). Every hit is re-checked against that author's newest event, so a replaced claim counts as revoked.

**Login.** The app issues a one-time nonce bound to its origin and an expiry. The user answers with either key: a Nostr kind `27235` event, or a
BCH signed message. The app verifies the answer locally, then looks up the other key.

| Module | Job |
|---|---|
| `src/cashaddr.js`, `src/bech32.js`, `src/bits.js`, `src/bytes.js` | encodings (CashAddr, legacy base58check, bech32/npub, hex/base64) |
| `src/bchmsg.js` | BCH signed-message verify (Electron Cash / Paytaca format) |
| `src/nostr.js` | NIP-01 id + BIP-340 verify (one verify path for everything) |
| `src/binding.js` | the two-way check, with a reason for every rejected claim |
| `src/relay.js` | publish, forward + reverse lookup, newest-wins, revocation |
| `src/compose.js` | builds the event, keeping the user's other claims |
| `src/pay.js` | npub → verified address → payment URI |
| `src/auth.js` | challenge-response login with either key |
| `src/sign.js` | BCH signed message + Nostr event signing, used only by the demo's throwaway-key path |
| `bin/blaze-bch.js` | CLI: `text <npub>`, `verify <event.json>` |
| `web/` | demo pages (`index.html` try it without a wallet + look up + link, `login.html`), with exactly the noble files they load vendored |

## Trust and limits

- **Relays are not trusted to tell the truth.** A relay can hide events but cannot forge them, because every event and proof is verified in the
  browser. Reading several relays covers one that hides events or is stale.
- **No server of ours** stores anything. The demo pages are static files.
- **Revocation works by replacement.** It is only as fast as the relays that receive the newer event. A BCH-transaction commitment would give a
  global order, and that is a stretch goal not built yet.
- **Scope:** P2PKH addresses with compressed keys, which is what Paytaca and Electron Cash make today. Uncompressed-key signatures are refused
  with a reason. P2SH or multisig claims are out of scope.
- The page builds the DOM only with `textContent`, so relay data is never inserted as HTML.

## Run it

- `npm test`: unit tests, including every vector set and a real-WebSocket relay test (Node ≥ 22, no network).
- `node bin/blaze-bch.js text <npub>` / `node bin/blaze-bch.js verify event.json`
- Serve the repo root with any static server and open `web/index.html`. `?relays=wss://a,wss://b` picks other relays; plain `ws://` is
  allowed only for localhost testing.

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
| Pay by identity (`src/pay.js`) + binding composer that keeps the user's other claims (`src/compose.js`) | done |
| Demo page (`web/`): look up npub ⇄ address, payment link, link an address with a NIP-07 signer + pasted BCH signature | done: lookup checked in headless Chrome on the live relays; the full link flow (injected test signer → publish → lookups → payment link, an existing GitHub claim kept) checked in headless Chrome against a local relay (`?relays=ws://127.0.0.1:…`, `test/local-relay.mjs`) |
| Try it without a wallet (`web/try.js`, `src/sign.js`): two throwaway keys made in the page run compose → sign → verify, then a copied proof, a borrowed address and an edited event are each refused | done: checked in headless Chrome (all three refused with their reasons, no network requests, no page errors, no overflow at 390 px) |
| Login (`src/auth.js`): one-time nonce bound to the origin + expiry; answer with a Nostr kind 27235 event OR a BCH signed message; replay, wrong origin/nonce/kind, stale or expired answers refused | done: library + `web/login.html` (both paths checked in headless Chrome against a local relay; a reused signature is refused) |

Run the tests with `npm test` (Node ≥ 22). There are two runtime dependencies, pinned exactly: `@noble/curves` 2.4.0 and `@noble/hashes` 2.4.0.

## For other apps

[`docs/NIP-39-bch.md`](docs/NIP-39-bch.md) proposes `bch` as a NIP-39 claim type: tag format, proof bytes, the two checks, discovery both ways and revocation. Any Nostr client or BCH wallet can adopt it without this code.

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
