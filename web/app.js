// Demo page glue. All logic lives in ../src (unit-tested); relay data is untrusted, so it only ever reaches the DOM via textContent.
import { DEFAULT_RELAYS, lookupByPubkey, lookupByAddress, publish } from '../src/relay.js';
import { verificationText, verifyBinding } from '../src/binding.js';
import { composeBinding } from '../src/compose.js';
import { paymentUri } from '../src/pay.js';
import { npubDecode, npubEncode } from '../src/bech32.js';

const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
};
const show = (box, ...nodes) => box.replaceChildren(...nodes);
const line = (text, cls) => el('div', text, cls);

$('relays').textContent = `Relays: ${DEFAULT_RELAYS.map((u) => u.replace('wss://', '')).join(' · ')}`;

// ---- look up: npub -> address (+ payment link), or address -> npubs ----
let payAddress = null;
$('lookup').onclick = async () => {
  const q = $('q').value.trim();
  const out = $('lookupOut');
  $('pay').hidden = true;
  show(out, line('Asking the relays…', 'muted'));
  try {
    if (q.startsWith('npub1')) {
      const r = await lookupByPubkey(npubDecode(q), DEFAULT_RELAYS);
      if (!r || !r.verified.length) return show(out, line('No verified BCH address for this npub.', 'bad'));
      payAddress = r.verified[0];
      $('pay').hidden = false;
      return show(out, line('✓ Nostr signature and ✓ BCH signature both verified here.', 'ok'),
        ...r.verified.map((a) => line(a)), ...r.rejected.map((x) => line(`✗ ${x.address}: ${x.reason}`, 'bad')));
    }
    const found = await lookupByAddress(q, DEFAULT_RELAYS);
    if (!found.length) return show(out, line('No npub currently proves this address.', 'bad'));
    show(out, line('✓ Current bindings (both signatures verified here):', 'ok'), ...found.map((x) => line(x.npub)));
  } catch (e) {
    show(out, line(`Not an npub or a cashaddr: ${e.message}`, 'bad'));
  }
};

$('payBtn').onclick = () => {
  const out = $('payOut');
  try {
    const amount = $('amount').value.trim();
    const uri = paymentUri(payAddress, amount ? { amount } : {});
    const a = el('a', uri);
    a.href = uri;
    show(out, a, line('Opens your BCH wallet.', 'muted'));
  } catch (e) {
    show(out, line(e.message, 'bad'));
  }
};

// ---- link: NIP-07 pubkey, text to sign, pasted BCH signature, compose + sign + publish ----
let pubkey = null;
$('connect').onclick = async () => {
  if (!window.nostr) return show($('who'), document.createTextNode('No NIP-07 signer found in this browser.'));
  try {
    pubkey = await window.nostr.getPublicKey();
    const npub = npubEncode(pubkey);
    $('who').textContent = npub;
    $('text').value = verificationText(npub);
    $('publish').disabled = false;
  } catch (e) {
    $('who').textContent = `Signer refused: ${e.message}`;
  }
};

$('copy').onclick = () => navigator.clipboard?.writeText($('text').value);

$('publish').onclick = async () => {
  const out = $('pubOut');
  $('publish').disabled = true;
  try {
    show(out, line('Reading your current claims…', 'muted'));
    const current = await lookupByPubkey(pubkey, DEFAULT_RELAYS);
    const unsigned = composeBinding({ pubkey, address: $('addr').value.trim().toLowerCase(), proof: $('sig').value.trim(),
      current: current?.event ?? null });
    const signed = await window.nostr.signEvent(unsigned);
    const check = verifyBinding(signed);
    if (!check.ok || !check.verified.length) throw new Error(`signed event does not verify (${check.reason ?? 'no bound address'})`);
    show(out, line('Publishing…', 'muted'));
    const res = await publish(signed, DEFAULT_RELAYS);
    show(out, line(`✓ Bound ${check.verified.join(', ')}`, 'ok'),
      ...res.map((r) => line(`${r.url.replace('wss://', '')}: ${r.ok ? 'accepted' : `refused (${r.message})`}`, r.ok ? 'muted' : 'bad')));
  } catch (e) {
    show(out, line(e.message, 'bad'));
  } finally {
    $('publish').disabled = false;
  }
};
