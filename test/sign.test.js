// Signers for the "try it without a wallet" demo: throwaway keys made in the page, never stored, never sent anywhere.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomSecretKey, bchAddressFromSecret, signBchMessage, signNostrEvent } from '../src/sign.js';
import { verifyBchMessage } from '../src/bchmsg.js';
import { verifyEvent } from '../src/nostr.js';
import { verifyBinding, verificationText } from '../src/binding.js';
import { composeBinding } from '../src/compose.js';
import { npubEncode } from '../src/bech32.js';
import { BCH_SK, NOSTR_SK, bchAddress, signBch, nostrPubkey } from './helpers.js';

test('bchAddressFromSecret = the P2PKH cashaddr of the compressed key, any prefix', () => {
  assert.equal(bchAddressFromSecret(BCH_SK), bchAddress(BCH_SK));
  assert.equal(bchAddressFromSecret(BCH_SK, 'bchtest'), bchAddress(BCH_SK, 'bchtest'));
});

test('signBchMessage = the Electron Cash / Paytaca format (byte-identical to the test signer) and verifies', () => {
  const text = 'Verifying that I control the following Nostr public key: npub1test';
  const sig = signBchMessage(BCH_SK, text);
  assert.equal(sig, signBch(BCH_SK, text));
  assert.deepEqual(verifyBchMessage({ address: bchAddressFromSecret(BCH_SK), message: text, signature: sig }), { ok: true });
  assert.equal(verifyBchMessage({ address: bchAddressFromSecret(BCH_SK), message: `${text}x`, signature: sig }).ok, false);
});

test('signNostrEvent fills pubkey, id and a valid BIP-340 signature', () => {
  const ev = signNostrEvent(NOSTR_SK, { kind: 1, created_at: 1763128800, tags: [], content: 'hi' });
  assert.equal(ev.pubkey, nostrPubkey(NOSTR_SK));
  assert.deepEqual(verifyEvent(ev), { ok: true });
  assert.equal(verifyEvent({ ...ev, content: 'hj' }).ok, false);
});

test('throwaway keys run the whole binding flow: compose, sign, verify both checks', () => {
  const nostrSk = randomSecretKey();
  const bchSk = randomSecretKey();
  assert.equal(nostrSk.length, 32);
  assert.notDeepEqual(nostrSk, bchSk);
  const pubkey = signNostrEvent(nostrSk, { kind: 1, created_at: 1, tags: [], content: '' }).pubkey;
  const address = bchAddressFromSecret(bchSk);
  const proof = signBchMessage(bchSk, verificationText(npubEncode(pubkey)));
  const ev = signNostrEvent(nostrSk, composeBinding({ pubkey, address, proof, current: null, now: 1763128800 }));
  const r = verifyBinding(ev);
  assert.equal(r.ok, true);
  assert.deepEqual(r.verified, [address]);
});

test('signNostrEvent refuses an unsigned event that names another pubkey', () => {
  assert.throws(() => signNostrEvent(NOSTR_SK, { pubkey: nostrPubkey(BCH_SK), kind: 1, created_at: 1, tags: [], content: '' }), /not this key/);
});
