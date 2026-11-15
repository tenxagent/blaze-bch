import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { hexToBytes, bytesToHex, base64ToBytes, bytesToBase64 } from '../src/bytes.js';

test('hex round trip, lowercase out, odd length and non-hex rejected', () => {
  const b = Uint8Array.of(0, 1, 0xab, 0xff);
  assert.equal(bytesToHex(b), '0001abff');
  assert.deepEqual(hexToBytes('0001ABff'), b);
  assert.deepEqual(hexToBytes(''), new Uint8Array(0));
  for (const bad of ['0', 'zz', '0g', null]) assert.throws(() => hexToBytes(bad), /hex/);
});

test('base64 matches the standard alphabet and rejects junk', () => {
  const b = new TextEncoder().encode('wrong');
  assert.equal(bytesToBase64(b), 'd3Jvbmc=');
  assert.deepEqual(base64ToBytes('d3Jvbmc='), b);
  for (const bad of ['not base64!', 'd3Jvbmc', '', null]) assert.throws(() => base64ToBytes(bad), /base64/);
});

test('library code never uses Node-only Buffer (the demo page runs the same modules in a browser)', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of readdirSync(dir)) assert.doesNotMatch(readFileSync(new URL(f, dir), 'utf8'), /\bBuffer\b/, f);
});
