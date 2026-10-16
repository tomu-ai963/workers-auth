/**
 * One application secret, several purpose-bound keys.
 *
 * The app configures a single `secret` (plus, while rotating, `previousSecrets`).
 * HKDF-SHA256 turns each one into:
 *   - `otpKey`    — HMAC key for email codes
 *   - `pepperKey` — HMAC key applied to a PIN before PBKDF2
 *   - `keyId`     — a short public handle stored next to every hash, so a row
 *                   can be verified against the secret that actually made it
 *
 * Distinct `info` strings make the keys independent: knowing one tells you
 * nothing about another, and none of them reveal the secret. `keyId` is safe
 * to store and log — it is an HKDF output, not a hash of the secret itself.
 */

const encoder = /* @__PURE__ */ new TextEncoder();

const HKDF_SALT = 'workers-auth/device-auth/v1';

/** Below this, a secret is more likely a placeholder than a key. */
export const MIN_SECRET_LENGTH = 32;

export type DerivedKeys = {
  keyId: string;
  otpKey: CryptoKey;
  pepperKey: CryptoKey;
};

export type KeyRing = {
  /** Used for everything newly written. */
  current: DerivedKeys;
  /** current + previous, by keyId. Used only to verify. */
  byId: ReadonlyMap<string, DerivedKeys>;
};

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += (bytes[i] as number).toString(16).padStart(2, '0');
  return out;
}

async function deriveKeys(secret: string): Promise<DerivedKeys> {
  const base = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, [
    'deriveKey',
    'deriveBits',
  ]);
  const params = (info: string) => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: encoder.encode(HKDF_SALT),
    info: encoder.encode(info),
  });
  const hmac = { name: 'HMAC', hash: 'SHA-256', length: 256 };
  const [otpKey, pepperKey, idBits] = await Promise.all([
    crypto.subtle.deriveKey(params('otp-hmac'), base, hmac, false, ['sign']),
    crypto.subtle.deriveKey(params('pin-pepper'), base, hmac, false, ['sign']),
    crypto.subtle.deriveBits(params('key-id'), base, 64),
  ]);
  return { keyId: toHex(new Uint8Array(idBits)), otpKey, pepperKey };
}

/** Below this many estimated bits, a secret is refused. */
export const MIN_SECRET_ENTROPY_BITS = 96;

/**
 * Shannon entropy of the string's own character distribution, times its
 * length. Not a measure of how the secret was generated — only a cheap way to
 * catch the obvious placeholders (`'a'.repeat(32)`, `changemechangeme…`,
 * a word typed four times) before they reach production. 32 random hex
 * characters score ~115; `openssl rand -base64 48` scores ~350.
 */
export function estimateEntropyBits(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h * value.length;
}

/** Throws without echoing the value — a secret must never reach an error message. */
export function assertSecret(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length < MIN_SECRET_LENGTH) {
    throw new TypeError(`deviceAuth: ${label} must be a string of at least ${MIN_SECRET_LENGTH} characters`);
  }
  if (new Set(value).size < 10 || estimateEntropyBits(value) < MIN_SECRET_ENTROPY_BITS) {
    throw new TypeError(
      `deviceAuth: ${label} looks low-entropy; generate it with \`openssl rand -base64 48\``,
    );
  }
}

export async function buildKeyRing(secret: string, previousSecrets: readonly string[] = []): Promise<KeyRing> {
  const current = await deriveKeys(secret);
  const byId = new Map<string, DerivedKeys>([[current.keyId, current]]);
  for (const previous of previousSecrets) {
    if (previous === secret) continue;
    const keys = await deriveKeys(previous);
    if (!byId.has(keys.keyId)) byId.set(keys.keyId, keys);
  }
  return { current, byId };
}

export async function hmacBytes(key: CryptoKey, message: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
}

export async function hmacHex(key: CryptoKey, message: string): Promise<string> {
  return toHex(await hmacBytes(key, message));
}
