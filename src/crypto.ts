/**
 * Crypto primitives. Web Crypto only — no runtime dependencies.
 *
 * Rules enforced here:
 *  - secrets are generated with `crypto.getRandomValues` (never Math.random)
 *  - secrets are stored as SHA-256 hex, never raw
 *  - every secret comparison goes through a constant-time path
 */

const encoder = /* @__PURE__ */ new TextEncoder();

/** 256 bits. The default size for every secret this SDK mints. */
export const SECRET_BYTES = 32;

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new TypeError('randomBytes: length must be a positive integer');
  }
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] as number);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64urlDecodeToString(value: string): string {
  return new TextDecoder().decode(base64urlDecode(value));
}

/** A fresh 256-bit secret, base64url encoded (43 chars, no padding). */
export function randomToken(bytes: number = SECRET_BYTES): string {
  return base64urlEncode(randomBytes(bytes));
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return out;
}

/** SHA-256 of a UTF-8 string, lowercase hex (64 chars). */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return toHex(new Uint8Array(digest));
}

export async function sha256Bytes(input: string | Uint8Array): Promise<Uint8Array> {
  const data = typeof input === 'string' ? encoder.encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

/**
 * Constant-time byte comparison. Both inputs MUST be the same length for the
 * guarantee to hold (all internal callers compare fixed-length digests).
 * Prefer {@link secretEquals} when lengths are attacker-influenced.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** Constant-time comparison of two fixed-length hex/ASCII strings. */
export function timingSafeEqual(a: string, b: string): boolean {
  return timingSafeEqualBytes(encoder.encode(a), encoder.encode(b));
}

/**
 * Length-independent constant-time equality: both sides are hashed first, so
 * neither the content nor the length of the inputs is observable through
 * timing. Use this whenever one side comes straight off the wire.
 */
export async function secretEquals(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256Bytes(a), sha256Bytes(b)]);
  return timingSafeEqualBytes(ha, hb);
}

/**
 * Verifies a raw secret against a stored SHA-256 hex hash, in constant time.
 * This is the only sanctioned way to check a stored credential.
 */
export async function verifySecretHash(raw: string, storedHex: string): Promise<boolean> {
  return timingSafeEqual(await sha256Hex(raw), storedHex);
}

/**
 * A short, non-reversible id for a secret, safe to put in logs. 12 hex chars of
 * SHA-256 identifies a session for debugging without exposing the credential.
 */
export async function fingerprint(secret: string): Promise<string> {
  return (await sha256Hex(secret)).slice(0, 12);
}
