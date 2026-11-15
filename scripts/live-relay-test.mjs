// Step 3 of the live relay test (after make-live-events.mjs and a leak-gate scan of both files).
// Publishes binding.json, checks forward + reverse lookup (all relays, then the #i lookup relay by relay), publishes revoke.json
// (same author, newer, no claim) and checks that both lookups now return nothing. Prints one JSON summary; exit 0 = all as expected.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { publish, lookupByPubkey, lookupByAddress } from '../src/relay.js';
import { verifyBinding } from '../src/binding.js';

export const RELAYS = ['wss://nos.lol', 'wss://relay.primal.net', 'wss://offchain.pub', 'wss://nostr.mom', 'wss://relay.nostr.net',
  'wss://relay.snort.social'];
const dir = process.argv[2];
const binding = JSON.parse(readFileSync(join(dir, 'binding.json'), 'utf8'));
const revoke = JSON.parse(readFileSync(join(dir, 'revoke.json'), 'utf8'));
const address = verifyBinding(binding).verified[0];
const opts = { timeoutMs: 10000 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const summary = { address, pubkey: binding.pubkey };

summary.publishBinding = (await publish(binding, RELAYS, opts)).map((r) => `${r.url} ${r.ok ? 'OK' : `NO (${r.message})`}`);
await sleep(3000);
const fwd = await lookupByPubkey(binding.pubkey, RELAYS, opts);
summary.forward = fwd?.verified ?? null;
summary.reverse = (await lookupByAddress(address, RELAYS, opts)).map((x) => x.npub);
summary.reverseByRelay = {};
for (const url of RELAYS) summary.reverseByRelay[url] = (await lookupByAddress(address, [url], opts)).length;

summary.publishRevoke = (await publish(revoke, RELAYS, opts)).map((r) => `${r.url} ${r.ok ? 'OK' : `NO (${r.message})`}`);
await sleep(3000);
summary.forwardAfterRevoke = (await lookupByPubkey(binding.pubkey, RELAYS, opts))?.verified ?? null;
summary.reverseAfterRevoke = (await lookupByAddress(address, RELAYS, opts)).length;

const ok = summary.forward?.[0] === address && summary.reverse.length === 1 && summary.forwardAfterRevoke?.length === 0
  && summary.reverseAfterRevoke === 0;
summary.allAsExpected = ok;
console.log(JSON.stringify(summary, null, 1));
process.exit(ok ? 0 : 1);
