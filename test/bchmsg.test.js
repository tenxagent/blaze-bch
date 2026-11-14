import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { legacyToCashaddr, decodeCashaddr, encodeCashaddr } from '../src/cashaddr.js';
import { verifyBchMessage, bchMessageBytes } from '../src/bchmsg.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/vectors.json', import.meta.url)));
const [C1, C2] = V.bch_signed_message.cases;
const addr1 = legacyToCashaddr(C1.legacy_addr);
const addr2 = legacyToCashaddr(C2.legacy_addr);

test('Electron Cash msg1: both compressed sigs (headers 31, 32) verify against the cashaddr', () => {
  C1.sigs_b64.forEach((sig, i) => {
    assert.equal(Buffer.from(sig, 'base64')[0], C1.headers[i]);
    assert.deepEqual(verifyBchMessage({ address: addr1, message: C1.msg, signature: sig }), { ok: true });
  });
});

test('uppercase form of the same cashaddr verifies too (compare decoded, not strings)', () => {
  const r = verifyBchMessage({ address: addr1.toUpperCase(), message: C1.msg, signature: C1.sigs_b64[0] });
  assert.equal(r.ok, true);
});

test('decision (a): uncompressed-key sigs (headers 27, 28) are rejected with a named reason', () => {
  C2.sigs_b64.forEach((sig, i) => {
    assert.equal(Buffer.from(sig, 'base64')[0], C2.headers[i]);
    assert.deepEqual(verifyBchMessage({ address: addr2, message: C2.msg, signature: sig }),
      { ok: false, reason: 'uncompressed-key-not-supported' });
  });
});

test('wrong sig/address pair is false, not an error', () => {
  assert.deepEqual(verifyBchMessage({ address: addr2, message: C1.msg, signature: C1.sigs_b64[0] }),
    { ok: false, reason: 'address-mismatch' });
});

test('a changed message no longer matches the address', () => {
  const r = verifyBchMessage({ address: addr1, message: C1.msg + '.', signature: C1.sigs_b64[0] });
  assert.equal(r.ok, false);
});

test('same key hash as a P2SH (type 1) address does not match', () => {
  const { hash } = decodeCashaddr(addr1);
  assert.deepEqual(verifyBchMessage({ address: encodeCashaddr('bitcoincash', 1, hash), message: C1.msg,
    signature: C1.sigs_b64[0] }), { ok: false, reason: 'address-mismatch' });
});

test('a signed message does not commit to a network: the same key on chipnet verifies', () => {
  const { hash } = decodeCashaddr(addr1);
  assert.deepEqual(verifyBchMessage({ address: encodeCashaddr('bchtest', 0, hash), message: C1.msg,
    signature: C1.sigs_b64[0] }), { ok: true });
});

test('the bytes "wrong" as a signature is an error, as in Electron Cash', () => {
  assert.throws(() => verifyBchMessage({ address: addr1, message: C1.msg,
    signature: Buffer.from('wrong').toString('base64') }), /signature/);
});

test('serialization: magic, compactSize(len) of the UTF-8 bytes, message', () => {
  const short = bchMessageBytes('Électron');
  assert.deepEqual([...short.subarray(0, 25)], [0x18, ...Buffer.from('Bitcoin Signed Message:\n')]);
  assert.equal(short[25], Buffer.byteLength('Électron'));
  const long = bchMessageBytes('a'.repeat(300));
  assert.deepEqual([...long.subarray(25, 28)], [0xfd, 0x2c, 0x01]);
  assert.equal(long.length, 25 + 3 + 300);
});
