#!/usr/bin/env node
// blaze-bch CLI.
//   blaze-bch text <npub>          print the exact text the BCH wallet signs (NIP-39 verification text)
//   blaze-bch verify <event.json>  check a kind 10011 event: exit 0 = at least one BCH address bound, 1 = none, 2 = bad input
import { readFileSync } from 'node:fs';
import { verificationText, verifyBinding } from '../src/binding.js';
import { npubDecode } from '../src/bech32.js';

const USAGE = 'usage: blaze-bch text <npub> | blaze-bch verify <event.json>';
const [cmd, arg] = process.argv.slice(2);

function fail(msg, code = 2) {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
}

if (cmd === 'text' && arg) {
  try {
    npubDecode(arg);
  } catch (e) {
    fail(`not an npub: ${e.message}`);
  }
  process.stdout.write(`${verificationText(arg)}\n`);
} else if (cmd === 'verify' && arg) {
  let event;
  try {
    event = JSON.parse(readFileSync(arg, 'utf8'));
  } catch (e) {
    fail(`cannot read event: ${e.message}`);
  }
  const r = verifyBinding(event);
  process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
  process.exit(r.ok && r.verified.length > 0 ? 0 : 1);
} else {
  fail(USAGE);
}
