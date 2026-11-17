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

Only the Nostr key can do this. A signed message, once given, stays valid inside any event that carries it, so the BCH key cannot
withdraw it off-chain (for example after the Nostr key is lost). The optional on-chain commitment below lets the BCH key do that.

## On-chain commitment (optional)

The address's own key can state, in a BCH transaction, which Nostr key it belongs to, or that it belongs to none. Blocks give these
statements one order for everyone.

- **Bind:** input 0 is a P2PKH spend by the address's key (unlocking script `<signature> <public key>`), and one output is
  `OP_RETURN <"N39B"> <32-byte x-only Nostr pubkey>`, in hex `6a 04 4e333942 20 <pubkey>`.
- **Revoke:** the same, with an empty push: `6a044e33394200`.
- Input 0's signature (ECDSA or BCH Schnorr) must use `SIGHASH_ALL|FORKID`, so nobody can move the commitment into another
  transaction. A transaction with more than one `N39B` output, or with a malformed one, is not a commitment.
- **Order:** for each address, the newest **confirmed** commitment counts: the highest block, and within one block the later
  transaction. An unconfirmed commitment counts once it confirms.

**Precedence.** A verifier that reads the chain combines its state with the off-chain check:

| On-chain state of the address | Result |
|---|---|
| none | the off-chain check decides, as above |
| bound to P | only P's claim counts, and P's newest kind `10011` must still claim the address |
| revoked | no claim of the address counts |
| unknown (servers unreachable or disagreeing) | the off-chain result, marked *not checked on chain* |

The chain never creates a claim by itself. The Nostr key must claim the address too, so nobody can attach an address to someone
else's npub.

**Reading it.** Electrum-protocol servers (Fulcrum) list an address's transactions by scripthash, the byte-reversed `sha256` of
its locking script. A server cannot forge a commitment, because the verifier itself checks that:

- each transaction hashes to its id;
- the parent output is this address's P2PKH lock;
- the signature is valid over the parent's value.

A server can hide a transaction or misstate its height, so read several servers run by different operators and take the union
of their histories. Answer *unknown* when fewer than two answer, or when they disagree on a commitment's height.

The prefix `N39B` (`0x4e333942`) was not in the BCH OP_RETURN prefix registry (`bitcoincash.org`, `etc/protocols.csv`) on
2026-11-17.

## Reference implementation

This repository: `src/binding.js` (verify), `src/relay.js` (discovery + revocation), `src/compose.js` (keep the user's other claims when
adding one), with test vectors from the CashAddr spec, BIP-340 and Electron Cash. On 2026-11-15, publish, both lookups and revocation passed on
six public relays (`docs/live-relay-test-2026-11-15.json`).

The on-chain commitment: `src/bchtx.js` (transaction bytes + FORKID digest; all 494 Bitcoin Cash Node sighash vectors), `src/commit.js`
(format, signer check, newest-wins, precedence), `src/committx.js` (build + sign one), `src/bchschnorr.js` (BCH Schnorr; Bitcoin Cash
Node's 13 vectors) and `src/fulcrum.js` (several servers). Two real mainnet spends, one ECDSA and one Schnorr, verify with it. No
`N39B` commitment has been broadcast on mainnet yet.
