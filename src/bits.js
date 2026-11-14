// Regroup a list of `from`-bit values into `to`-bit values. Strict when pad=false (no leftover non-zero bits, no extra group).
export function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) throw new Error('convertBits: value out of range');
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
    acc &= (1 << bits) - 1;
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || acc !== 0) {
    throw new Error('convertBits: invalid padding');
  }
  return out;
}
