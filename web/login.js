// Login demo glue. Logic: ../src/auth.js (challenge + verifier) and ../src/relay.js (find the other key). Relay data -> textContent only.
import { makeChallenge, challengeText, createLoginVerifier, refusalText, LOGIN_KIND } from '../src/auth.js';
import { relaysFromQuery, lookupByPubkey, lookupByAddress } from '../src/relay.js';
import { npubEncode } from '../src/bech32.js';

const $ = (id) => document.getElementById(id);
const line = (text, cls) => Object.assign(document.createElement('div'), { textContent: text, className: cls ?? '' });
const show = (box, ...nodes) => box.replaceChildren(...nodes);
const RELAYS = relaysFromQuery(location.search);
const verifier = createLoginVerifier();
let challenge;
const fresh = () => {
  challenge = makeChallenge({ origin: location.origin });
  $('chText').value = challengeText(challenge);
};
fresh();
$('relays').textContent = `Relays: ${RELAYS.map((u) => u.replace('wss://', '')).join(' · ')}`;

$('nostrLogin').onclick = async () => {
  const out = $('nostrOut');
  if (!window.nostr) return show(out, line('No NIP-07 signer found in this browser.', 'bad'));
  try {
    const signed = await window.nostr.signEvent({ kind: LOGIN_KIND, created_at: Math.floor(Date.now() / 1000), content: '',
      tags: [['u', challenge.origin], ['method', 'LOGIN'], ['challenge', challenge.nonce]] });
    const r = verifier.verifyNostr(signed, challenge);
    if (!r.ok) return show(out, line(`Refused: ${refusalText(r.reason)}`, 'bad'));
    show(out, line(`✓ Logged in as ${npubEncode(r.pubkey)}`, 'ok'), line('Looking for a bound BCH address…', 'muted'));
    const b = await lookupByPubkey(r.pubkey, RELAYS);
    show(out, line(`✓ Logged in as ${npubEncode(r.pubkey)}`, 'ok'),
      b?.verified?.length ? line(`BCH address (both signatures verified): ${b.verified.join(', ')}`) : line('No BCH address bound to this key.', 'muted'));
  } catch (e) {
    show(out, line(`Signer refused: ${e.message}`, 'bad'));
  } finally {
    fresh();
  }
};

$('bchLogin').onclick = async () => {
  const out = $('bchOut');
  const r = verifier.verifyBch({ address: $('addr').value.trim(), signature: $('sig').value.trim() }, challenge);
  if (!r.ok) return show(out, line(`Refused: ${refusalText(r.reason)}`, 'bad'));
  show(out, line(`✓ Logged in as ${r.address}`, 'ok'), line('Looking for a bound npub…', 'muted'));
  const found = await lookupByAddress(r.address, RELAYS);
  show(out, line(`✓ Logged in as ${r.address}`, 'ok'),
    found.length ? line(`Nostr identity (both signatures verified): ${found.map((x) => x.npub).join(', ')}`) : line('No npub bound to this address.', 'muted'));
  fresh();
};
