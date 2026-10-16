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

/** Commonly chosen PINs that none of the structural rules below catch. */
const DENYLIST = new Set([
  '123321',
  '654456',
  '147258',
  '258369',
  '369258',
  '159753',
  '357159',
  '147852',
  '963852',
  '789456',
  '456123',
  '102030',
  '112358',
  '520520',
  '520131',
  '131420',
]);

/**
 * Rejects PINs an attacker would try first. Assumes `isPinFormat(pin)`.
 *
 *   - every digit the same           000000, 777777
 *   - ascending / descending runs    123456, 345678, 987654, 012345
 *   - repeating 2- or 3-digit blocks 121212, 123123
 *   - doubled / tripled digits       112233, 111222
 *   - a short list of common picks   147258, 123321, ...
 */
export function isWeakPin(pin: string): boolean {
  const d = Array.from(pin, (ch) => ch.charCodeAt(0) - 48);
  if (d.every((x) => x === d[0])) return true;

  let up = true;
  let down = true;
  for (let i = 1; i < d.length; i++) {
    if ((d[i] as number) !== (d[i - 1] as number) + 1) up = false;
    if ((d[i] as number) !== (d[i - 1] as number) - 1) down = false;
  }
  if (up || down) return true;

  if (pin.slice(0, 2).repeat(3) === pin) return true;
  if (pin.slice(0, 3).repeat(2) === pin) return true;
  if (pin[0] === pin[1] && pin[2] === pin[3] && pin[4] === pin[5]) return true;
  if (pin[0] === pin[1] && pin[1] === pin[2] && pin[3] === pin[4] && pin[4] === pin[5]) return true;

  return DENYLIST.has(pin);
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
