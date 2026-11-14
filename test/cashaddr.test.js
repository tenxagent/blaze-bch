import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  verifyChecksum, encodeCashaddr, decodeCashaddr, decodeLegacy, legacyToCashaddr, parseClaim,
} from '../src/cashaddr.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/vectors.json', import.meta.url)));
const hex = (u8) => Buffer.from(u8).toString('hex').toUpperCase();

test('spec checksum strings pass polymod (payloads are invalid on purpose, so checksum only)', () => {
  for (const s of V.cashaddr.checksum_valid) assert.equal(verifyChecksum(s), true, s);
});

test('one flipped character breaks the checksum', () => {
  for (const s of V.cashaddr.checksum_valid) {
    const i = s.length - 3;
    const c = s[i] === 'q' ? 'p' : 'q';
    assert.equal(verifyChecksum(s.slice(0, i) + c + s.slice(i + 1)), false, s);
  }
});

test('legacy base58 addresses translate to the spec cashaddr (3 P2PKH + 3 P2SH)', () => {
  for (const { legacy, cashaddr } of V.cashaddr.legacy_translation) {
    assert.equal(legacyToCashaddr(legacy), cashaddr);
    const d = decodeCashaddr(cashaddr);
    const l = decodeLegacy(legacy);
    assert.equal(d.type, l.type);
    assert.equal(hex(d.hash), hex(l.hash));
  }
});

test('larger vectors: 160-512 bit payloads x types 0/1/15 encode and decode exactly', () => {
  assert.equal(V.cashaddr.larger.length, 32);
  for (const { cashaddr, type, payload_hex } of V.cashaddr.larger) {
    const prefix = cashaddr.slice(0, cashaddr.indexOf(':'));
    assert.equal(encodeCashaddr(prefix, type, Buffer.from(payload_hex, 'hex')), cashaddr);
    const d = decodeCashaddr(cashaddr);
    assert.equal(d.prefix, prefix);
    assert.equal(d.type, type);
    assert.equal(hex(d.hash), payload_hex.toUpperCase());
  }
});

test('uppercase is accepted, mixed case is rejected', () => {
  const a = V.cashaddr.legacy_translation[0].cashaddr;
  assert.equal(hex(decodeCashaddr(a.toUpperCase()).hash), hex(decodeCashaddr(a).hash));
  const mixed = a.slice(0, -1) + a.slice(-1).toUpperCase();
  assert.throws(() => decodeCashaddr(mixed), /mixed case/);
});

test('a cashaddr without its prefix is rejected (claims always carry the network prefix)', () => {
  const a = V.cashaddr.legacy_translation[0].cashaddr;
  assert.throws(() => decodeCashaddr(a.slice(a.indexOf(':') + 1)), /prefix/);
});

test('a bad checksum is rejected on decode', () => {
  const a = V.cashaddr.legacy_translation[0].cashaddr;
  assert.throws(() => decodeCashaddr(a.slice(0, -1) + (a.endsWith('a') ? 'q' : 'a')), /checksum/);
});

test('legacy base58check rejects a corrupted address', () => {
  const l = V.cashaddr.legacy_translation[0].legacy;
  assert.throws(() => decodeLegacy(l.slice(0, -1) + (l.endsWith('u') ? 'v' : 'u')), /checksum/);
});

test('NIP-39 claim splits at the FIRST colon only', () => {
  const a = V.cashaddr.legacy_translation[0].cashaddr;
  assert.deepEqual(parseClaim(`bch:${a}`), { platform: 'bch', identity: a });
  assert.throws(() => parseClaim('bch'), /claim/);
});
