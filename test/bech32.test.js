import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bech32Decode, bech32Encode, npubEncode, npubDecode } from '../src/bech32.js';
import { convertBits } from '../src/bits.js';

const B = JSON.parse(readFileSync(new URL('./fixtures/bech32.json', import.meta.url)));

test('BIP-173: every valid string decodes and re-encodes to its lowercase form', () => {
  assert.equal(B.bech32_valid.length, 7);
  for (const s of B.bech32_valid) {
    const { hrp, words } = bech32Decode(s);
    assert.equal(bech32Encode(hrp, words), s.toLowerCase(), s);
  }
});

test('BIP-173: every invalid string is rejected', () => {
  assert.equal(B.bech32_invalid.length, 8);
  for (const { s, reason } of B.bech32_invalid) assert.throws(() => bech32Decode(s), undefined, `${s}: ${reason}`);
});

test('NIP-19: hex pubkey <-> npub, both spec examples', () => {
  assert.equal(B.npub.length, 2);
  for (const { hex, npub } of B.npub) {
    assert.equal(npubEncode(hex), npub);
    assert.equal(npubDecode(npub), hex);
  }
});

test('npubDecode refuses another prefix and a wrong payload length', () => {
  const { words } = bech32Decode(B.npub[0].npub);
  assert.throws(() => npubDecode(bech32Encode('nsec', words)), /npub/);
  const short = convertBits([...Buffer.from(B.npub[0].hex, 'hex').subarray(0, 31)], 8, 5, true);
  assert.throws(() => npubDecode(bech32Encode('npub', short)), /32 bytes/);
});

test('npubEncode refuses anything but 64 hex chars', () => {
  for (const bad of ['', 'zz', B.npub[0].hex.slice(2), B.npub[0].hex.toUpperCase() + '0', null]) {
    assert.throws(() => npubEncode(bad), /hex/);
  }
});
