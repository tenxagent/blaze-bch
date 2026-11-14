// Writes test/fixtures/nip01-event.json: an unsigned kind-10011 event from the PUBLIC throwaway test key.
// scripts/nip01-id.py then adds "python_id" (a second, independent NIP-01 serializer).
import { writeFileSync } from 'node:fs';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { TEST_SK_LABEL } from '../test/test-key.js';
const sk = sha256(new TextEncoder().encode(TEST_SK_LABEL));
const event = {
  pubkey: Buffer.from(schnorr.getPublicKey(sk)).toString('hex'),
  created_at: 1700000000,
  kind: 10011,
  tags: [['i', 'bch:bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a', 'proof'], ['i', 'github:example', 'gist']],
  content: 'line1\nline2 "quoted" \\ back\ttab \u00e9 \u{1F525} \u0001 \u2028 end',
};
writeFileSync(new URL('../test/fixtures/nip01-event.json', import.meta.url), JSON.stringify({ event }, null, 1) + '\n');
