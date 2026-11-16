// Static-site checks for the hosted demo (GitHub Pages serves the repo root as-is): the root page sends visitors to web/,
// and every relative link, script and import the pages use points at a file that exists in the repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname, normalize } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const local = (ref) => !/^([a-z]+:|#|\/\/)/i.test(ref);
const resolves = (fromFile, ref) => {
  const p = normalize(join(ROOT, dirname(fromFile), ref.split(/[?#]/)[0]));
  if (!p.startsWith(ROOT)) return false;
  return existsSync(p) && (statSync(p).isFile() || existsSync(join(p, 'index.html')));
};

test('root index.html redirects to the demo in web/', () => {
  const html = read('index.html');
  assert.match(html, /<meta http-equiv="refresh" content="0; url=\.\/web\/">/);
  assert.match(html, /<a href="\.\/web\/">/, 'plain link for browsers that ignore the refresh');
  assert.ok(resolves('index.html', './web/'));
});

test('every relative href/src in the pages exists', () => {
  for (const page of ['index.html', 'web/index.html', 'web/login.html']) {
    const refs = [...read(page).matchAll(/\b(?:href|src)="([^"]+)"/g)].map((m) => m[1]).filter(local);
    assert.ok(refs.length > 0, page);
    for (const ref of refs) assert.ok(resolves(page, ref), `${page} -> ${ref}`);
  }
});

test('every relative import in the page scripts exists (they load ../src directly)', () => {
  for (const script of ['web/app.js', 'web/login.js']) {
    const refs = [...read(script).matchAll(/\bfrom\s+'(\.[^']+)'/g)].map((m) => m[1]);
    assert.ok(refs.length > 0, script);
    for (const ref of refs) assert.ok(resolves(script, ref), `${script} -> ${ref}`);
  }
});
