import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { VENDORED, vendorFiles } from '../scripts/vendor-noble.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const walk = (d, r = '') => readdirSync(join(d, r)).flatMap((f) => (statSync(join(d, r, f)).isDirectory() ? walk(d, join(r, f)) : [join(r, f)]));

test('web/vendor = exactly the import graph the page needs, byte-identical to the pinned noble 2.4.0 packages', () => {
  const want = vendorFiles();
  assert.ok(want.some(([p, r]) => p === 'curves' && r === 'secp256k1.js'));
  for (const [pkg, rel] of want) {
    assert.ok(readFileSync(join(ROOT, 'web/vendor', VENDORED[pkg], rel)).equals(readFileSync(join(ROOT, 'node_modules/@noble', pkg, rel))), `${pkg}/${rel}`);
  }
  const have = walk(join(ROOT, 'web/vendor')).sort();
  assert.deepEqual(have, want.map(([p, r]) => join(VENDORED[p], r)).sort(), 'no extra files');
  for (const out of Object.values(VENDORED)) {
    assert.equal(JSON.parse(readFileSync(join(ROOT, 'web/vendor', out, 'package.json'), 'utf8')).version, '2.4.0');
  }
});
