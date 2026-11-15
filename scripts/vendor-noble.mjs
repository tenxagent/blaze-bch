// Copies ONLY the files the browser page needs (the import graph of secp256k1 + sha2 + legacy) from the installed,
// lockfile-pinned @noble/curves + @noble/hashes 2.4.0, plus each LICENSE and package.json, into web/vendor/.
// The page then runs the exact bytes the tests ran against, and nothing unused is published.
import { cpSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, normalize, relative } from 'node:path';
const ROOT = new URL('..', import.meta.url).pathname;
const NM = join(ROOT, 'node_modules/@noble');
export const VENDORED = { curves: 'noble-curves', hashes: 'noble-hashes' };
const ENTRY = [['curves', 'secp256k1.js'], ['hashes', 'sha2.js'], ['hashes', 'legacy.js']];

// -> [[pkg, relPath], ...] for every file reached by import/export ... from, plus LICENSE + package.json per package.
export function vendorFiles() {
  const seen = new Set();
  const queue = ENTRY.map(([p, f]) => join(NM, p, f));
  while (queue.length) {
    const f = queue.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of readFileSync(f, 'utf8').matchAll(/^\s*(?:import|export)[^'"]*?from\s+['"]([^'"]+)['"]/gm)) {
      if (m[1].startsWith('.')) queue.push(normalize(join(dirname(f), m[1])));
      else if (m[1].startsWith('@noble/')) queue.push(join(ROOT, 'node_modules', m[1]));
    }
  }
  const out = [...seen].map((f) => relative(NM, f).split('/')).map(([pkg, ...rest]) => [pkg, rest.join('/')]);
  for (const pkg of Object.keys(VENDORED)) out.push([pkg, 'LICENSE'], [pkg, 'package.json']);
  return out.sort();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  for (const [pkg, rel] of vendorFiles()) {
    const to = join(ROOT, 'web/vendor', VENDORED[pkg], rel);
    mkdirSync(dirname(to), { recursive: true });
    cpSync(join(NM, pkg, rel), to);
  }
  console.log(`vendored ${vendorFiles().length} files into web/vendor/`);
}
