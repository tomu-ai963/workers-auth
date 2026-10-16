/**
 * The rate-limit key for a client IP.
 *
 * IPv4 addresses are keyed as-is. IPv6 addresses are keyed by their /64:
 * a single subscriber, VPS or cloud instance is routinely handed a whole /64,
 * so keying the full address would give one attacker 2^64 independent
 * buckets. IPv4-mapped IPv6 (`::ffff:203.0.113.7`) is keyed as the IPv4
 * address it carries.
 *
 * Anything that does not parse is keyed verbatim (lower-cased) — it still
 * gets *a* bucket, just not a shared one.
 */

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEXTET_RE = /^[0-9a-f]{1,4}$/;

function ipv4(value: string): string | null {
  const m = IPV4_RE.exec(value);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts.join('.') : null;
}

function expandIpv6(value: string): number[] | null {
  let text = value;
  // An embedded IPv4 tail ("::ffff:1.2.3.4", "64:ff9b::1.2.3.4") becomes two hextets.
  const tail = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (tail) {
    const v4 = ipv4(tail[2] as string);
    if (!v4) return null;
    const [a, b, c, d] = v4.split('.').map(Number) as [number, number, number, number];
    text = `${tail[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (s: string) => (s === '' ? [] : s.split(':'));
  const head = parse(halves[0] as string);
  const rest = halves.length === 2 ? parse(halves[1] as string) : [];
  if (![...head, ...rest].every((h) => HEXTET_RE.test(h))) return null;
  const missing = 8 - head.length - rest.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  return [...head, ...Array<string>(missing).fill('0'), ...rest].map((h) => parseInt(h, 16));
}

export function ipRateLimitKey(raw: string): string {
  const value = raw.trim().toLowerCase().replace(/^\[(.*)\]$/, '$1').split('%')[0] as string;
  const v4 = ipv4(value);
  if (v4) return v4;
  if (!value.includes(':')) return value;

  const hextets = expandIpv6(value);
  if (!hextets) return value;
  // ::ffff:0:0/96 — an IPv4 address in IPv6 clothing.
  if (hextets.slice(0, 5).every((h) => h === 0) && hextets[5] === 0xffff) {
    const [hi, lo] = [hextets[6] as number, hextets[7] as number];
    return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join('.');
  }
  return `${hextets
    .slice(0, 4)
    .map((h) => h.toString(16))
    .join(':')}::/64`;
}
