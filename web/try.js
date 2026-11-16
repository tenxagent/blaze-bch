// "Try it without a wallet": two throwaway keys made in this page (never stored, nothing published) run the same code path
// as a real link, then three tampering attempts show what the checks refuse. Output only via textContent.
import { randomSecretKey, bchAddressFromSecret, signBchMessage, signNostrEvent } from '../src/sign.js';
import { verificationText, verifyBinding } from '../src/binding.js';
import { composeBinding } from '../src/compose.js';
import { npubEncode } from '../src/bech32.js';

const $ = (id) => document.getElementById(id);
const line = (text, cls) => {
  const d = document.createElement('div');
  d.textContent = text;
  if (cls) d.className = cls;
  return d;
};
const pre = (obj) => {
  const p = document.createElement('pre');
  p.textContent = JSON.stringify(obj, null, 1);
  return p;
};
const short = (s) => (s.length > 28 ? `${s.slice(0, 16)}…${s.slice(-8)}` : s);
const pubOf = (sk) => signNostrEvent(sk, { kind: 1, created_at: 0, tags: [], content: '' }).pubkey;
const verdict = (r, label) => {
  if (!r.ok) return line(`✗ ${label}: event refused (${r.reason})`, 'bad');
  if (r.verified.length) return line(`✓ ${label}: both signatures check out, ${short(r.verified[0])} is bound to ${short(r.npub)}`, 'ok');
  return line(`✗ ${label}: ${r.rejected.map((x) => x.reason).join(', ')}`, 'bad');
};

let run = null;

$('try').onclick = () => {
  const nostrSk = randomSecretKey();
  const bchSk = randomSecretKey();
  const pubkey = pubOf(nostrSk);
  const npub = npubEncode(pubkey);
  const address = bchAddressFromSecret(bchSk);
  const text = verificationText(npub);
  const proof = signBchMessage(bchSk, text);
  const event = signNostrEvent(nostrSk, composeBinding({ pubkey, address, proof }));
  run = { nostrSk, pubkey, address, proof, event };
  $('tryOut').replaceChildren(
    line(`1. Nostr key → ${npub}`),
    line(`2. BCH key → ${address}`),
    line(`3. The BCH key signs “${text}” → ${short(proof)}`),
    line('4. The Nostr key signs this kind 10011 event:'),
    pre(event),
    verdict(verifyBinding(event), '5. Check'),
  );
  $('tamper').hidden = false;
  $('tamperOut').replaceChildren();
};

// A thief copies the proof into an event signed by THEIR Nostr key.
$('t1').onclick = () => {
  const thief = randomSecretKey();
  const ev = signNostrEvent(thief, { pubkey: pubOf(thief), kind: 10011, created_at: run.event.created_at, tags: run.event.tags, content: '' });
  $('tamperOut').replaceChildren(verdict(verifyBinding(ev), 'Proof copied into another Nostr key’s event'),
    line('The BCH signature names the first npub, so it proves nothing for any other key.', 'muted'));
};

// The Nostr key claims an address it does not control, reusing the proof it has.
$('t2').onclick = () => {
  const other = bchAddressFromSecret(randomSecretKey());
  const ev = signNostrEvent(run.nostrSk, { ...run.event, tags: [['i', `bch:${other}`, run.proof]] });
  $('tamperOut').replaceChildren(verdict(verifyBinding(ev), 'Claiming someone else’s address'),
    line('The signature was made by the first BCH key, whose hash is not in this address.', 'muted'));
};

// Someone edits the event after it was signed.
$('t3').onclick = () => {
  const ev = { ...run.event, content: 'edited after signing' };
  $('tamperOut').replaceChildren(verdict(verifyBinding(ev), 'Event edited after signing'),
    line('The event id no longer matches its content, so the Nostr signature does not cover it.', 'muted'));
};
