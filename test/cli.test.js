import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verificationText } from '../src/binding.js';
import { npubEncode } from '../src/bech32.js';
import { NOSTR_SK, BCH_SK, nostrPubkey, bchAddress, signBch, signEvent } from './helpers.js';

const CLI = new URL('../bin/blaze-bch.js', import.meta.url).pathname;
const run = (args) => {
  try {
    return { code: 0, out: execFileSync('node', [CLI, ...args], { encoding: 'utf8' }) };
  } catch (e) {
    return { code: e.status, out: `${e.stdout}${e.stderr}` };
  }
};
const npub = npubEncode(nostrPubkey(NOSTR_SK));
const addr = bchAddress(BCH_SK);

test('`text <npub>` prints exactly the text the BCH wallet must sign', () => {
  const r = run(['text', npub]);
  assert.equal(r.code, 0);
  assert.equal(r.out, `${verificationText(npub)}\n`);
});

test('`text` refuses something that is not an npub', () => {
  const r = run(['text', 'nsec1xyz']);
  assert.notEqual(r.code, 0);
});

test('`verify <event.json>` prints JSON and exits 0 when at least one address is bound', () => {
  const dir = mkdtempSync(join(tmpdir(), 'blaze-cli-'));
  const f = join(dir, 'ev.json');
  writeFileSync(f, JSON.stringify(signEvent(NOSTR_SK, { tags: [['i', `bch:${addr}`, signBch(BCH_SK, verificationText(npub))]] })));
  const r = run(['verify', f]);
  assert.equal(r.code, 0);
  const j = JSON.parse(r.out);
  assert.deepEqual(j.verified, [addr]);
});

test('`verify` exits 1 when nothing is bound, 2 on unreadable input', () => {
  const dir = mkdtempSync(join(tmpdir(), 'blaze-cli-'));
  const f = join(dir, 'ev.json');
  writeFileSync(f, JSON.stringify(signEvent(NOSTR_SK, { tags: [['i', `bch:${addr}`, signBch(BCH_SK, 'wrong text')]] })));
  assert.equal(run(['verify', f]).code, 1);
  writeFileSync(f, '{not json');
  assert.equal(run(['verify', f]).code, 2);
});

test('no command prints usage and exits 2', () => {
  const r = run([]);
  assert.equal(r.code, 2);
  assert.match(r.out, /usage/i);
});
