/**
 * Credential kinds — the one extension point for new login methods.
 *
 * Everything around a credential is shared and kind-agnostic: the
 * `auth_credentials` row, the per-account failure counter and lockout, audit
 * events, session minting, trusted devices. A kind only answers two
 * questions — how to turn enrolment input into stored `material`, and whether
 * a login attempt matches that material.
 *
 * Adding passkeys means adding a `passkeyCredential` next to `pinCredential`
 * (plus its own challenge table/migration). No existing table, column, or
 * route changes: `'passkey'` is already allowed by the `type` CHECK.
 */

import { base64urlDecode, base64urlEncode, randomBytes, timingSafeEqualBytes } from '../crypto.js';
import { hmacBytes, type KeyRing } from './keys.js';

export type CredentialType = 'pin' | 'passkey';

/** Stored as JSON in `auth_credentials.material`. Shape is the kind's business. */
export type CredentialMaterial = Record<string, unknown>;

export type CredentialContext = {
  keys: KeyRing;
};

export type CredentialVerifyResult = {
  ok: boolean;
  /**
   * Set when the material should be rewritten after a successful match —
   * e.g. it was made with a rotated-out secret or an older cost setting.
   */
  upgraded?: CredentialMaterial;
};

export interface CredentialKind<TInput> {
  readonly type: CredentialType;
  /**
   * Whether a login with this kind is only accepted alongside a valid
   * trusted-device proof. A PIN is a knowledge factor over a tiny space, so it
   * must be; a passkey carries its own proof of possession and would not be.
   */
  readonly requiresTrustedDevice: boolean;
  enroll(input: TInput, ctx: CredentialContext): Promise<CredentialMaterial>;
  verify(input: TInput, material: CredentialMaterial, ctx: CredentialContext): Promise<CredentialVerifyResult>;
}

// ---------------------------------------------------------------------------
// PIN
// ---------------------------------------------------------------------------

export const PIN_LENGTH = 6;
const PIN_RE = /^\d{6}$/;

/** WebCrypto PBKDF2 in Cloudflare Workers is capped at 100,000 iterations. */
export const MAX_PBKDF2_ITERATIONS = 100_000;
export const MIN_PBKDF2_ITERATIONS = 1_000;
export const DEFAULT_PBKDF2_ITERATIONS = MAX_PBKDF2_ITERATIONS;

const SALT_BYTES = 16;
const HASH_BITS = 256;

export function isPinFormat(pin: unknown): pin is string {
  return typeof pin === 'string' && PIN_RE.test(pin);
}

/**
 * The 179 all-digit, 6-character entries of SecLists'
 * `Passwords/Common-Credentials/10k-most-common.txt`, in their published
 * (frequency) order, plus a few well-known picks it does not contain.
 *
 * Source: https://github.com/danielmiessler/SecLists (MIT; notice in
 * THIRD_PARTY_NOTICES), fetched 2026-10-16,
 * file sha256 68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce.
 * These are passwords rather than PINs, but numeric passwords and PINs are
 * chosen the same way; many of them are also caught by the structural rules
 * below, and that overlap is deliberate.
 */
const COMMON_PINS = new Set(
  (
    '123456 696969 111111 654321 123123 666666 121212 131313 000000 112233 222222 777777 987654 232323 ' +
    '555555 123321 999999 333333 888888 444444 101010 420420 147147 212121 242424 007007 123654 789456 ' +
    '252525 159753 141414 202020 151515 323232 314159 456789 246810 111222 181818 171717 147258 102030 ' +
    '363636 343434 454545 424242 272727 098765 159357 147852 191919 321321 010101 565656 362436 456123 ' +
    '741852 123789 505050 262626 161616 000007 636363 313131 666999 010203 134679 420247 124578 353535 ' +
    '456456 545454 303030 321654 135790 143143 898989 787878 911911 515151 234567 909090 474747 989898 ' +
    '012345 196969 142536 282828 404040 727272 200000 369369 292929 987456 969696 100000 525252 311311 ' +
    '223344 757575 585858 187187 112358 789789 753951 555666 717171 686868 635241 987987 414141 434343 ' +
    '575757 090909 000001 420000 747474 373737 120676 655321 963852 646464 124038 123457 852456 030303 ' +
    '767676 616161 515000 656565 626262 336699 951753 494949 383838 456654 818181 222333 102938 737373 ' +
    '789987 484848 121314 878787 070462 427900 676767 123987 159159 112211 535353 100100 332211 778899 ' +
    '321123 797979 464646 543210 050505 445566 333666 789654 020202 616913 199999 123098 753159 666777 ' +
    '902100 222777 456321 515051 606060 159951 142857 789123 393939 868686 567890 ' +
    // Not in the list above, but common enough to name explicitly.
    '654456 258369 369258 357159 520520 520131 131420 147369 258456 112112'
  ).split(' '),
);

/**
 * Straight 3-key lines on a phone keypad, both directions:
 *
 *     1 2 3
 *     4 5 6      rows, columns (including 5-8-0) and both diagonals
 *     7 8 9
 *       0
 *
 * A PIN made of two of these (147258, 159357, 123654, 741852) is a shape,
 * not a number, and is guessed as one.
 */
const KEYPAD_LINES = new Set(
  ['123', '456', '789', '147', '258', '369', '580', '159', '357'].flatMap((l) => [l, [...l].reverse().join('')]),
);

export type WeakPinOptions = {
  /**
   * Also reject PINs that read as a date: DDMMYY, MMDDYY, YYMMDD, YYYYMM,
   * MMYYYY. Off by default — it removes roughly a tenth of the PIN space, and
   * whether a birthday is a "weak" PIN is a product decision.
   */
  rejectDateLike?: boolean;
};

function isMonth(n: number): boolean {
  return n >= 1 && n <= 12;
}

function isDay(n: number): boolean {
  return n >= 1 && n <= 31;
}

function isDateLike(pin: string): boolean {
  const two = (i: number) => Number(pin.slice(i, i + 2));
  const [a, b, c] = [two(0), two(2), two(4)];
  if (isDay(a) && isMonth(b)) return true; // DDMMYY
  if (isMonth(a) && isDay(b)) return true; // MMDDYY
  if (isMonth(b) && isDay(c)) return true; // YYMMDD
  const year4 = (s: string) => /^(19|20)\d\d$/.test(s);
  if (year4(pin.slice(0, 4)) && isMonth(c)) return true; // YYYYMM
  if (isMonth(a) && year4(pin.slice(2))) return true; // MMYYYY
  return false;
}

/**
 * Rejects PINs an attacker would try first. Assumes `isPinFormat(pin)`.
 *
 *   - fewer than 3 distinct digits     000000, 101010, 112211, 100000
 *   - runs, wrapping round 9→0         123456, 987654, 890123, 098765
 *   - palindromes                      123321, 456654
 *   - repeating 2- or 3-digit blocks   121212, 123123
 *   - doubled / tripled digits         112233, 111222
 *   - two keypad lines                 147258, 159357, 123654
 *   - the common-PIN list above        696969, 314159, 420420, ...
 *   - dates, when `rejectDateLike`     010190, 199001
 */
export function isWeakPin(pin: string, options: WeakPinOptions = {}): boolean {
  const d = Array.from(pin, (ch) => ch.charCodeAt(0) - 48);
  if (new Set(d).size < 3) return true;

  let up = true;
  let down = true;
  for (let i = 1; i < d.length; i++) {
    if ((d[i] as number) !== ((d[i - 1] as number) + 1) % 10) up = false;
    if ((d[i] as number) !== ((d[i - 1] as number) + 9) % 10) down = false;
  }
  if (up || down) return true;

  if ([...pin].reverse().join('') === pin) return true;
  if (pin.slice(0, 2).repeat(3) === pin) return true;
  if (pin.slice(0, 3).repeat(2) === pin) return true;
  if (pin[0] === pin[1] && pin[2] === pin[3] && pin[4] === pin[5]) return true;
  if (pin[0] === pin[1] && pin[1] === pin[2] && pin[3] === pin[4] && pin[4] === pin[5]) return true;
  if (KEYPAD_LINES.has(pin.slice(0, 3)) && KEYPAD_LINES.has(pin.slice(3))) return true;
  if (COMMON_PINS.has(pin)) return true;

  return options.rejectDateLike === true && isDateLike(pin);
}

type PinMaterial = {
  alg: 'pbkdf2-sha256';
  iterations: number;
  salt: string;
  hash: string;
  /** keyId of the secret whose pepper was applied. */
  pepperVer: string;
};

function isPinMaterial(value: CredentialMaterial): value is PinMaterial {
  return (
    value['alg'] === 'pbkdf2-sha256' &&
    typeof value['iterations'] === 'number' &&
    typeof value['salt'] === 'string' &&
    typeof value['hash'] === 'string' &&
    typeof value['pepperVer'] === 'string'
  );
}

/**
 * PBKDF2-SHA256 over HMAC(pepper, pin).
 *
 * The pepper is what actually protects a 6-digit PIN: there are only 10^6 of
 * them, so a leaked table without the pepper falls to brute force no matter
 * the iteration count. PBKDF2 is the second line, for when the pepper leaks too.
 */
async function derive(pin: string, pepperKey: CryptoKey, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const peppered = await hmacBytes(pepperKey, pin);
  const key = await crypto.subtle.importKey('raw', peppered as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    key,
    HASH_BITS,
  );
  return new Uint8Array(bits);
}

export type PinCredentialOptions = { iterations?: number };

export function pinCredential(options: PinCredentialOptions = {}): CredentialKind<string> {
  const iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw new TypeError(
      `deviceAuth: pin.iterations must be an integer between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}`,
    );
  }

  async function enroll(pin: string, ctx: CredentialContext): Promise<CredentialMaterial> {
    const salt = randomBytes(SALT_BYTES);
    const hash = await derive(pin, ctx.keys.current.pepperKey, salt, iterations);
    const material: PinMaterial = {
      alg: 'pbkdf2-sha256',
      iterations,
      salt: base64urlEncode(salt),
      hash: base64urlEncode(hash),
      pepperVer: ctx.keys.current.keyId,
    };
    return material;
  }

  return {
    type: 'pin',
    requiresTrustedDevice: true,
    enroll,
    async verify(pin, material, ctx) {
      if (!isPinMaterial(material)) return { ok: false };
      // A secret dropped from `previousSecrets` can no longer verify its PINs.
      // That is the documented end of a rotation, not an error.
      const keys = ctx.keys.byId.get(material.pepperVer);
      if (!keys) return { ok: false };
      const expected = base64urlDecode(material.hash);
      const actual = await derive(pin, keys.pepperKey, base64urlDecode(material.salt), material.iterations);
      if (!timingSafeEqualBytes(actual, expected)) return { ok: false };

      const stale = material.pepperVer !== ctx.keys.current.keyId || material.iterations !== iterations;
      return stale ? { ok: true, upgraded: await enroll(pin, ctx) } : { ok: true };
    },
  };
}
