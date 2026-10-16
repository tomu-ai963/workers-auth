/**
 * PIN + trusted device + email code authentication.
 *
 *   new device:     email -> 6-digit code -> session; the device is registered
 *                   as trusted; set a PIN if the account has none
 *   trusted device: PIN only (device proof + PIN, never PIN alone)
 *   3 PIN failures: the account's PIN login stops until an email code succeeds
 *
 * This module sends no email (`sendCode` is injected) and mints sessions
 * through the `Auth` it is given, so cookie/session config, the session store
 * and `onEvent` are all shared with the rest of the SDK.
 *
 * Mount: `app.route('/auth/device', device.routes())`.
 */

import { Hono, type Context, type MiddlewareHandler } from 'hono';

import { getCookie, serializeCookie, serializeCookieDeletion } from '../cookie.js';
import { fingerprint, randomBytes, randomToken, sha256Hex, timingSafeEqual, verifySecretHash } from '../crypto.js';
import { verifyCsrf } from '../csrf.js';
import { applyNoStore } from '../headers.js';
import type { Auth } from '../index.js';
import {
  AUTH_META_KEY,
  clearSessionCookies,
  readCookieSession,
  sessionToUser,
  toSessionInfo,
  type AuthEvent,
} from '../middleware.js';
import { bearerSessionToken, readBearerSession } from '../providers/session-bearer.js';
import { INTERNAL_AUTH_META, type InternalAuthMeta } from '../routes.js';
import type { AuthProvider, AuthUser, Clock, Session, SessionStore } from '../types.js';
import {
  isPinFormat,
  isWeakPin as defaultIsWeakPin,
  pinCredential,
  type CredentialKind,
} from './credentials.js';
import { ipRateLimitKey } from './ip.js';
import { assertSecret, buildKeyRing, hmacHex, type KeyRing } from './keys.js';
import { isDeviceBoundSessionStore } from './sessions.js';
import type { DeviceAuthStore, DeviceInfo, DeviceRecord } from './store.js';

export {
  DEFAULT_PBKDF2_ITERATIONS,
  isPinFormat,
  isWeakPin,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  pinCredential,
  type CredentialContext,
  type CredentialKind,
  type CredentialMaterial,
  type CredentialType,
  type CredentialVerifyResult,
  type PinCredentialOptions,
  type WeakPinOptions,
} from './credentials.js';
export { ipRateLimitKey } from './ip.js';
export { estimateEntropyBits, MIN_SECRET_ENTROPY_BITS, MIN_SECRET_LENGTH } from './keys.js';
export {
  deviceBoundSessionStore,
  isDeviceBoundSessionStore,
  type DeviceBoundSessionStoreOptions,
} from './sessions.js';
export {
  d1DeviceAuthStore,
  type CredentialRecord,
  type D1DeviceAuthStoreOptions,
  type DeviceAuthStore,
  type DeviceAuthStoreCleanup,
  type DeviceInfo,
  type DeviceRecord,
  type EmailCodeRecord,
  type GuardState,
  type ReservedEmailCode,
} from './store.js';

/** Header carrying the device token in `transport: 'response'` mode. */
export const DEVICE_TOKEN_HEADER = 'x-device-token';

/** Every JSON body these routes accept fits in far less. */
export const MAX_BODY_BYTES = 4096;

const SEC = 1000;
const HOUR_SEC = 60 * 60;
const DAY_SEC = 24 * HOUR_SEC;

export type DeviceAuthLimits = {
  /** Minimum gap between two codes to the same address. Default: 60. */
  resendCooldownSec?: number;
  /** Codes per address per hour. Default: 5. */
  codesPerEmailPerHour?: number;
  /** `/email/start` calls per IP (IPv6: per /64) per hour. Default: 20. */
  startsPerIpPerHour?: number;
  /** `/email/verify` calls per IP (IPv6: per /64) per hour. Default: 60. */
  verifiesPerIpPerHour?: number;
  /** `/pin/login` calls per IP (IPv6: per /64) per hour. Default: 60. */
  pinLoginsPerIpPerHour?: number;
};

export type DeviceAuthOptions = {
  /**
   * The result of `createAuth()`. Its store must be wrapped with
   * `deviceBoundSessionStore()` and able to `revokeAllForUser()`; any
   * `sessionBearer()` provider in it must read that same wrapped store.
   */
  auth: Auth;
  store: DeviceAuthStore;
  /**
   * The one secret everything is derived from (HKDF): the email-code HMAC key
   * and the PIN pepper. At least 32 characters and not obviously low-entropy.
   * Generate with `openssl rand -base64 48`; keep it in `wrangler secret`.
   */
  secret: string;
  /**
   * Secrets being rotated out. Codes and PINs made with them still verify;
   * a PIN is re-hashed under `secret` on its next successful login.
   */
  previousSecrets?: readonly string[];
  /**
   * How the device token reaches the client — the app's choice:
   *   - `'cookie'`: frontend and API on the same site. Device token in an
   *     HttpOnly/Secure/SameSite=Lax cookie; cookie sessions; CSRF-checked.
   *   - `'response'`: frontend and API on different sites. Device token and a
   *     short-lived bearer session token come back in the JSON body; the app
   *     stores them and sends `x-device-token` / `Authorization: Bearer`.
   */
  transport: 'cookie' | 'response';
  /**
   * Delivers the code. Called for every valid-looking address, known or not.
   *
   * Do NOT branch on whether the address has an account (e.g. "only send to
   * registered users"): `/email/start` waits for this call, so a send that
   * happens for some addresses and not others shows up in the response time
   * and gives the answer away. Send to every address, or swallow the unknown
   * case only after doing the same amount of work.
   */
  sendCode: (email: string, code: string) => Promise<void>;
  /**
   * Delivery failures go here rather than into the response (that would be an
   * oracle). The error is whatever your provider threw, and it may echo the
   * request it failed on — recipient, subject, or the body with the code in
   * it. Log a status code or error name, not the whole object.
   */
  onSendError?: (error: unknown) => void;
  /**
   * Turns user input into the address everything is keyed on: the code row,
   * the per-address limits, `resolveUser`, and the device record. Default:
   * trim + lower-case. If your accounts treat `a.b+tag@gmail.com` and
   * `ab@gmail.com` as one user, do that here — not only in `resolveUser` —
   * or every spelling gets its own rate-limit budget against the same
   * account. The result must still look like an address.
   */
  normalizeEmail?: (raw: string) => string;
  /**
   * Maps a verified (normalised) address to the account. Default: id = email.
   * Return null to refuse (e.g. sign-up closed). Also called on every PIN
   * login with the address the device was registered under; it must return
   * the same id.
   */
  resolveUser?: (email: string) => AuthUser | null | Promise<AuthUser | null>;
  /** Base name of the device cookie (prefix follows the session cookie). Default: `device`. */
  deviceCookieName?: string;
  device?: {
    /** Extended by every PIN login and by a repeat email login on the same device. Default: 90 days. */
    idleTtlSec?: number;
    /** Hard ceiling from registration. Default: 365 days. */
    absoluteTtlSec?: number;
  };
  pin?: {
    /** PBKDF2 iterations, 1,000–100,000. Default: 100,000. */
    iterations?: number;
    /** Consecutive failures before lockout. Default: 3. */
    maxAttempts?: number;
    /** Extra weak-PIN rule, applied on top of the built-in one. */
    isWeakPin?: (pin: string) => boolean;
    /** Also refuse PINs that read as dates (DDMMYY, MMDDYY, YYMMDD, YYYYMM, MMYYYY). Default: false. */
    rejectDateLike?: boolean;
    /**
     * When an existing PIN is replaced, revoke the account's other trusted
     * devices *and every session of the account* — including the one making
     * the change, which then logs in again with the new PIN. Default: false.
     */
    revokeOtherDevicesOnChange?: boolean;
  };
  emailCode?: {
    /** Default: 600 (10 minutes). */
    ttlSec?: number;
    /** Wrong guesses allowed per code; a resend does not refill them. Default: 5. */
    maxAttempts?: number;
    /** 6 (default) or 8. Each extra digit makes a guess 10x less likely. */
    digits?: 6 | 8;
    /**
     * Failed verifications allowed per address across all of its codes, per
     * `failureWindowSec`. Once reached, `/email/start` and `/email/verify`
     * for that address answer 429 until the window passes: new-device login
     * by email is blocked for that long, PIN login on trusted devices is not
     * affected. Default: 10.
     */
    maxFailuresPerEmail?: number;
    /** Default: 86,400 (24 hours). */
    failureWindowSec?: number;
  };
  /** How recent an email verification `POST /pin` requires. Default: 600. */
  freshEmailAuthSec?: number;
  /** `transport: 'response'` only: bearer session lifetime, no sliding. Default: 43,200 (12 hours). */
  bearerSessionTtlSec?: number;
  limits?: DeviceAuthLimits;
  /**
   * The client IP for per-IP limits (IPv6 is bucketed by /64). Default:
   * `CF-Connecting-IP`, which Cloudflare's edge sets and overwrites — a
   * client cannot spoof it, and `X-Forwarded-For` is never read.
   *
   * Behind another proxy (a Worker in front of this one that builds fresh
   * requests, or a non-Cloudflare reverse proxy) every request can carry the
   * proxy's address, putting all users in one bucket. Then supply a function
   * that reads the header your proxy *sets* — never one a client can send.
   */
  getClientIp?: (req: Request) => string | null;
  /**
   * Refuse requests whose client IP cannot be determined (`400
   * client_ip_required`) instead of skipping per-IP limits for them.
   * Default: false.
   */
  requireClientIp?: boolean;
  /**
   * Bot-defence hook (Turnstile, etc.), run before `/email/start` sends and
   * before `/pin/login` does anything costly. Return false — or throw — to
   * refuse with `403 bot_check_failed`. `req` is a fresh clone; read your
   * token from its headers or body.
   */
  botCheck?: (req: Request, action: 'email_start' | 'pin_login') => boolean | Promise<boolean>;
  /**
   * Off by default. When set, `/email/verify` answers `503
   * temporarily_unavailable` to everyone while, within `windowSec`, at least
   * `minFailures` verifications failed and they make up at least
   * `maxFailureRatio` of all verifications — a brake on a distributed
   * guessing run. The trade: whoever can cause that many failures can use it
   * to stop email login for everybody, so set `minFailures` well above your
   * normal traffic.
   */
  circuitBreaker?: {
    minFailures: number;
    /** Default: 0.5. */
    maxFailureRatio?: number;
    /** Default: 600. */
    windowSec?: number;
  };
  clock?: Clock;
};

export type DeviceAuth = {
  routes(): Hono;
  /**
   * Gate for sensitive app routes: requires a session minted by an email-code
   * verification within `maxAgeSec` (default: `freshEmailAuthSec`).
   */
  requireFreshEmailAuth(maxAgeSec?: number): MiddlewareHandler;
  listDevices(userId: string): Promise<DeviceInfo[]>;
  /** Revokes one device; the sessions minted on it stop working at once. */
  revokeDevice(userId: string, deviceId: string): Promise<boolean>;
  /** Revokes every device of the account and every session of the account. */
  revokeAllDevices(userId: string): Promise<number>;
  hasPin(userId: string): Promise<boolean>;
};

const MAX_EMAIL_LENGTH = 320;
const DEVICE_TOKEN_RE = /^([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/;
const COOKIE_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function defaultNormalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function looksLikeEmail(email: string): boolean {
  return email.length > 2 && email.length <= MAX_EMAIL_LENGTH && /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(email);
}

/** Uniform n-digit code: rejection sampling, so no residue is more likely than another. */
export function generateEmailCode(digits: 6 | 8 = 6): string {
  const space = 10 ** digits;
  const limit = Math.floor(0x1_0000_0000 / space) * space;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    const value = buf[0] as number;
    if (value < limit) return String(value % space).padStart(digits, '0');
  }
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += (bytes[i] as number).toString(16).padStart(2, '0');
  return out;
}

function positive(value: number | undefined, fallback: number, label: string, integer = false): number {
  const v = value ?? fallback;
  if (!Number.isFinite(v) || v <= 0 || (integer && !Number.isInteger(v))) {
    throw new TypeError(`deviceAuth: ${label} must be a positive ${integer ? 'integer' : 'number'}`);
  }
  return v;
}

type JsonBody = { tooLarge: false; body: Record<string, unknown> | null } | { tooLarge: true };

/**
 * Reads at most `MAX_BODY_BYTES`. `Content-Length` is checked first and the
 * stream is counted as it is read, so a chunked or understated body cannot
 * make the Worker buffer or parse more than the limit.
 */
async function readJson(c: Context): Promise<JsonBody> {
  const declared = Number(c.req.header('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return { tooLarge: true };
  const stream = c.req.raw.clone().body;
  if (!stream) return { tooLarge: false, body: null };

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      return { tooLarge: true };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const body = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    return {
      tooLarge: false,
      body: body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : null,
    };
  } catch {
    return { tooLarge: false, body: null };
  }
}

function emailVerifiedAt(session: Session): number | null {
  const auth = session.meta?.[AUTH_META_KEY] as { emailVerifiedAt?: unknown } | undefined;
  return typeof auth?.emailVerifiedAt === 'number' ? auth.emailVerifiedAt : null;
}

function sessionDeviceId(session: Session): string | null {
  const auth = session.meta?.[AUTH_META_KEY] as { deviceId?: unknown } | undefined;
  return typeof auth?.deviceId === 'string' ? auth.deviceId : null;
}

function publicDevice(device: DeviceRecord) {
  return {
    deviceId: device.deviceId,
    idleExpiresAt: device.idleExpiresAt,
    absoluteExpiresAt: device.absoluteExpiresAt,
  };
}

function providerStore(provider: AuthProvider): SessionStore | null {
  const store = (provider as { sessionStore?: unknown }).sessionStore;
  return store && typeof (store as SessionStore).get === 'function' ? (store as SessionStore) : null;
}

export function deviceAuth(options: DeviceAuthOptions): DeviceAuth {
  const { auth, store, sendCode, onSendError, transport } = options;

  if (!auth || typeof auth.createSession !== 'function') {
    throw new TypeError('deviceAuth: auth (the result of createAuth) is required');
  }
  if (!store || store.atomic !== true) {
    throw new TypeError(
      'deviceAuth: the store must update counters atomically (atomic: true). Use d1DeviceAuthStore(); ' +
        'KV cannot enforce attempt limits under concurrent requests.',
    );
  }
  if (typeof sendCode !== 'function') {
    throw new TypeError('deviceAuth: sendCode is required (this SDK does not send email)');
  }
  if (transport !== 'cookie' && transport !== 'response') {
    throw new TypeError("deviceAuth: transport must be 'cookie' or 'response'");
  }
  assertSecret(options.secret, 'secret');
  const previousSecrets = options.previousSecrets ?? [];
  if (!Array.isArray(previousSecrets)) {
    throw new TypeError('deviceAuth: previousSecrets must be an array');
  }
  previousSecrets.forEach((s, i) => assertSecret(s, `previousSecrets[${i}]`));

  // Revoking a device must end its sessions (device-bound store), and
  // revoking all of them must end every session (revokeAllForUser). Both are
  // checked here, once, rather than discovered missing during an incident.
  if (!isDeviceBoundSessionStore(auth.config.store)) {
    throw new TypeError(
      "deviceAuth: the Auth's session store must be wrapped with deviceBoundSessionStore(store, deviceStore), " +
        'so that revoking a device ends the sessions minted on it',
    );
  }
  if (auth.config.store.canRevokeAllForUser !== true) {
    throw new TypeError(
      "deviceAuth: the Auth's session store cannot revokeAllForUser() (canRevokeAllForUser is false); " +
        'use d1SessionStore, or kvSessionStore with a revocationList',
    );
  }
  for (const provider of [...auth.config.providers, ...auth.config.callbackProviders]) {
    const read = providerStore(provider);
    if (read && !isDeviceBoundSessionStore(read)) {
      throw new TypeError(
        `deviceAuth: provider "${provider.name}" reads an unwrapped session store; ` +
          'pass it the same deviceBoundSessionStore(...) given to createAuth',
      );
    }
  }

  const deviceIdleMs = positive(options.device?.idleTtlSec, 90 * DAY_SEC, 'device.idleTtlSec') * SEC;
  const deviceAbsoluteMs = positive(options.device?.absoluteTtlSec, 365 * DAY_SEC, 'device.absoluteTtlSec') * SEC;
  if (deviceAbsoluteMs < deviceIdleMs) {
    throw new TypeError('deviceAuth: device.absoluteTtlSec must be >= device.idleTtlSec');
  }
  const pinMaxAttempts = positive(options.pin?.maxAttempts, 3, 'pin.maxAttempts', true);
  const codeTtlMs = positive(options.emailCode?.ttlSec, 600, 'emailCode.ttlSec') * SEC;
  const codeMaxAttempts = positive(options.emailCode?.maxAttempts, 5, 'emailCode.maxAttempts', true);
  const codeDigits = options.emailCode?.digits ?? 6;
  if (codeDigits !== 6 && codeDigits !== 8) {
    throw new TypeError('deviceAuth: emailCode.digits must be 6 or 8');
  }
  const codeRe = new RegExp(`^\\d{${codeDigits}}$`);
  const maxFailuresPerEmail = positive(options.emailCode?.maxFailuresPerEmail, 10, 'emailCode.maxFailuresPerEmail', true);
  const failureWindowSec = positive(options.emailCode?.failureWindowSec, DAY_SEC, 'emailCode.failureWindowSec');
  const freshMs = positive(options.freshEmailAuthSec, 600, 'freshEmailAuthSec') * SEC;
  const bearerTtlSec = positive(options.bearerSessionTtlSec, 12 * HOUR_SEC, 'bearerSessionTtlSec');
  const limits = {
    cooldownSec: positive(options.limits?.resendCooldownSec, 60, 'limits.resendCooldownSec'),
    perEmail: positive(options.limits?.codesPerEmailPerHour, 5, 'limits.codesPerEmailPerHour', true),
    startsPerIp: positive(options.limits?.startsPerIpPerHour, 20, 'limits.startsPerIpPerHour', true),
    verifiesPerIp: positive(options.limits?.verifiesPerIpPerHour, 60, 'limits.verifiesPerIpPerHour', true),
    pinLoginsPerIp: positive(options.limits?.pinLoginsPerIpPerHour, 60, 'limits.pinLoginsPerIpPerHour', true),
  };
  const breaker = options.circuitBreaker
    ? {
        minFailures: positive(options.circuitBreaker.minFailures, 0, 'circuitBreaker.minFailures', true),
        ratio: positive(options.circuitBreaker.maxFailureRatio, 0.5, 'circuitBreaker.maxFailureRatio'),
        windowSec: positive(options.circuitBreaker.windowSec, 600, 'circuitBreaker.windowSec'),
      }
    : null;
  if (breaker && breaker.ratio > 1) {
    throw new TypeError('deviceAuth: circuitBreaker.maxFailureRatio must be in (0, 1]');
  }
  const pin: CredentialKind<string> = pinCredential({ iterations: options.pin?.iterations });
  const extraWeak = options.pin?.isWeakPin;
  const rejectDateLike = options.pin?.rejectDateLike === true;
  const revokeOthersOnChange = options.pin?.revokeOtherDevicesOnChange === true;
  const getClientIp = options.getClientIp ?? ((req: Request) => req.headers.get('cf-connecting-ip'));
  const requireClientIp = options.requireClientIp === true;
  const botCheck = options.botCheck;
  const normalizeEmail = options.normalizeEmail ?? defaultNormalizeEmail;
  const clock: Clock = options.clock ?? auth.config.clock;
  const onEvent = (event: AuthEvent) => auth.config.onEvent(event);

  const resolveUser =
    options.resolveUser ??
    ((email: string): AuthUser => ({
      id: email,
      subjectType: 'user',
      rateLimitId: email,
      email,
      claims: { email },
    }));

  const deviceCookieBase = options.deviceCookieName ?? 'device';
  if (!COOKIE_TOKEN_RE.test(deviceCookieBase)) {
    throw new TypeError('deviceAuth: deviceCookieName must be a valid cookie token');
  }
  // Same prefix as the session cookie, so `dangerouslyAllowInsecureCookies`
  // in local dev applies here too and nothing else needs configuring.
  const cookiePrefix = /^__(Host|Secure)-/.exec(auth.config.cookie.sessionCookieName)?.[0] ?? '';
  const deviceCookieName = `${cookiePrefix}${deviceCookieBase}`;
  if (
    deviceCookieName === auth.config.cookie.sessionCookieName ||
    deviceCookieName === auth.config.cookie.csrfCookieName
  ) {
    throw new TypeError('deviceAuth: deviceCookieName must differ from the session and CSRF cookie names');
  }

  let ring: Promise<KeyRing> | undefined;
  const keys = () => (ring ??= buildKeyRing(options.secret, previousSecrets));

  const emailFingerprint = (email: string) => fingerprint(email);

  // -------------------------------------------------------------------------
  // Request plumbing
  // -------------------------------------------------------------------------

  type Gate = { ok: true; session: Session | null } | { ok: false; res: Response };

  /**
   * Cookie mode: every state-changing request is Origin-checked (and
   * double-submit-checked once a CSRF cookie exists), because the device and
   * session cookies are ambient credentials. Response mode carries nothing
   * ambient, so there is nothing to forge.
   */
  async function gate(c: Context): Promise<Gate> {
    if (transport === 'response') {
      return { ok: true, session: await readBearerSession(auth.config.store, c.req.raw) };
    }
    const current = await readCookieSession(c, auth.config);
    const csrf = await verifyCsrf({
      req: c.req.raw,
      cookieToken: current.csrfCookie,
      cookieAuthenticated: current.session !== null,
      requireOrigin: true,
      config: auth.config.csrf,
    });
    if (!csrf.ok) {
      onEvent({ type: 'csrf.failed', reason: csrf.reason });
      return { ok: false, res: c.json({ error: 'csrf_failed' as const }, 403) };
    }
    return { ok: true, session: current.session };
  }

  type Body = { ok: true; body: Record<string, unknown> | null } | { ok: false; res: Response };

  async function body(c: Context): Promise<Body> {
    const read = await readJson(c);
    if (read.tooLarge) return { ok: false, res: c.json({ error: 'payload_too_large' as const }, 413) };
    return { ok: true, body: read.body };
  }

  function retryAfter(c: Context, windowStart: number, windowSec: number, now: number): number {
    const retryAfterSec = Math.max(1, Math.ceil((windowStart + windowSec * SEC - now) / SEC));
    c.header('retry-after', String(retryAfterSec));
    return retryAfterSec;
  }

  async function rateLimited(
    c: Context,
    bucket: string,
    windowSec: number,
    limit: number,
    scope: string,
    now: number,
  ): Promise<Response | null> {
    const { count, windowStart } = await store.hitRateLimit(bucket, windowSec * SEC, now);
    if (count <= limit) return null;
    onEvent({ type: 'rate_limited', scope });
    return c.json({ error: 'rate_limited' as const, retryAfterSec: retryAfter(c, windowStart, windowSec, now) }, 429);
  }

  /**
   * Per-IP limit, keyed by IPv4 address or IPv6 /64. Returns a response to
   * send, or null to carry on. With no IP: refuse if `requireClientIp`,
   * otherwise skip (documented in SECURITY.md).
   */
  async function ipLimited(
    c: Context,
    action: string,
    limit: number,
    scope: string,
    now: number,
  ): Promise<Response | null> {
    const ip = getClientIp(c.req.raw);
    if (!ip) return requireClientIp ? c.json({ error: 'client_ip_required' as const }, 400) : null;
    return rateLimited(c, `${action}:ip:${ipRateLimitKey(ip)}`, HOUR_SEC, limit, scope, now);
  }

  async function botRefused(c: Context, action: 'email_start' | 'pin_login'): Promise<Response | null> {
    if (!botCheck) return null;
    let passed = false;
    try {
      passed = (await botCheck(c.req.raw.clone(), action)) === true;
    } catch {
      passed = false; // fail closed
    }
    if (passed) return null;
    onEvent({ type: 'bot_check.failed', action });
    return c.json({ error: 'bot_check_failed' as const }, 403);
  }

  function emailVerificationRequired(c: Context) {
    return c.json({ error: 'email_verification_required' as const }, 401);
  }

  function presentedDeviceToken(c: Context): string | null {
    const raw = transport === 'cookie' ? getCookie(c.req.raw, deviceCookieName) : c.req.header(DEVICE_TOKEN_HEADER);
    return raw ?? null;
  }

  /** The presented device, if it is real, unrevoked and unexpired. No PBKDF2 is ever spent here. */
  async function readDevice(c: Context, now: number): Promise<DeviceRecord | null> {
    const match = DEVICE_TOKEN_RE.exec(presentedDeviceToken(c) ?? '');
    if (!match) return null;
    const device = await store.findDevice(match[1] as string);
    if (!device) return null;
    if (!(await verifySecretHash(match[2] as string, device.secretHash))) return null;
    if (device.revokedAt !== null) return null;
    if (now >= device.idleExpiresAt || now >= device.absoluteExpiresAt) return null;
    return device;
  }

  function setDeviceCookie(c: Context, token: string, expiresAt: number, now: number) {
    if (transport !== 'cookie') return;
    c.header(
      'set-cookie',
      serializeCookie(deviceCookieName, token, {
        path: '/',
        httpOnly: true,
        secure: auth.config.cookie.secure,
        sameSite: 'Lax',
        maxAge: Math.max(1, Math.ceil((expiresAt - now) / SEC)),
      }),
      { append: true },
    );
  }

  function clearDeviceCookie(c: Context) {
    if (transport !== 'cookie') return;
    c.header(
      'set-cookie',
      serializeCookieDeletion(deviceCookieName, {
        path: '/',
        httpOnly: true,
        secure: auth.config.cookie.secure,
        sameSite: 'Lax',
      }),
      { append: true },
    );
  }

  async function registerDevice(
    c: Context,
    user: AuthUser,
    email: string,
    label: string | null,
    now: number,
  ): Promise<{ device: DeviceRecord; token: string }> {
    const deviceId = toHex(randomBytes(16));
    const secret = randomToken();
    const absoluteExpiresAt = now + deviceAbsoluteMs;
    const device: DeviceRecord = {
      deviceId,
      accountId: user.id,
      email,
      secretHash: await sha256Hex(secret),
      label,
      createdAt: now,
      lastUsedAt: now,
      idleExpiresAt: Math.min(now + deviceIdleMs, absoluteExpiresAt),
      absoluteExpiresAt,
      revokedAt: null,
    };
    await store.createDevice(device);
    const token = `${deviceId}.${secret}`;
    setDeviceCookie(c, token, device.idleExpiresAt, now);
    onEvent({ type: 'device.registered', userId: user.id, deviceId });
    return { device, token };
  }

  /** Mints the session in the shape this transport needs and returns the body fields for it. */
  async function mintSession(c: Context, user: AuthUser, internal: InternalAuthMeta): Promise<Record<string, unknown>> {
    if (transport === 'cookie') {
      await auth.createSession(c, user, { [INTERNAL_AUTH_META]: internal });
      return {};
    }
    const session = await auth.createSession(c, user, {
      transport: 'bearer',
      ttl: { idleTtlSec: bearerTtlSec, absoluteTtlSec: bearerTtlSec },
      [INTERNAL_AUTH_META]: internal,
    });
    return { sessionToken: bearerSessionToken(session.sid), sessionExpiresAt: session.absoluteExpiresAt };
  }

  /** Every session of the account, on every device and transport. */
  async function revokeAllSessions(c: Context | null, userId: string, reason: string) {
    await auth.config.store.revokeAllForUser(userId);
    onEvent({ type: 'sessions.revoked_all', userId, reason });
    if (c && transport === 'cookie') clearSessionCookies(c, auth.config);
  }

  function checkUser(user: AuthUser | null): user is AuthUser {
    return !!user && typeof user.rateLimitId === 'string' && user.rateLimitId.length > 0;
  }

  /** The address input normalised by the configured function, or null if it is not an address. */
  function readEmail(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    let email: unknown;
    try {
      email = normalizeEmail(value);
    } catch {
      return null;
    }
    return typeof email === 'string' && looksLikeEmail(email) ? email : null;
  }

  const failureBucket = (emailKey: string) => `otp-fail:${emailKey}`;
  const CB_ATTEMPTS = 'cb:email-verify:attempts';
  const CB_FAILURES = 'cb:email-verify:failures';

  // -------------------------------------------------------------------------
  // Routes
  // -------------------------------------------------------------------------

  function routes(): Hono {
    const app = new Hono();

    app.use('*', async (c, next) => {
      applyNoStore(c);
      await next();
    });

    /**
     * Same work and same answer for every address. Whether an account exists
     * is never consulted here — that is `resolveUser`'s job, after the code.
     */
    app.post('/email/start', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      const b = await body(c);
      if (!b.ok) return b.res;
      const email = readEmail(b.body?.['email']);
      if (!email) return c.json({ error: 'invalid_request' as const }, 400);

      const bot = await botRefused(c, 'email_start');
      if (bot) return bot;

      const now = clock();
      const ipHit = await ipLimited(c, 'otp-start', limits.startsPerIp, 'email_start_ip', now);
      if (ipHit) return ipHit;
      const emailKey = await sha256Hex(email);

      // A code the address could not verify anyway is not worth sending.
      const failures = await store.readRateLimit(failureBucket(emailKey), failureWindowSec * SEC, now);
      if (failures.count >= maxFailuresPerEmail) {
        onEvent({ type: 'rate_limited', scope: 'email_failures' });
        return c.json(
          { error: 'rate_limited' as const, retryAfterSec: retryAfter(c, failures.windowStart, failureWindowSec, now) },
          429,
        );
      }

      const cooled = await rateLimited(c, `otp-cool:${emailKey}`, limits.cooldownSec, 1, 'email_cooldown', now);
      if (cooled) return cooled;
      const capped = await rateLimited(c, `otp-email:${emailKey}`, HOUR_SEC, limits.perEmail, 'email_hourly', now);
      if (capped) return capped;

      const ring = await keys();
      const code = generateEmailCode(codeDigits);
      await store.putEmailCode({
        email,
        codeHash: await hmacHex(ring.current.otpKey, `${email}\n${code}`),
        keyId: ring.current.keyId,
        expiresAt: now + codeTtlMs,
        createdAt: now,
        attemptsResetAt: now + codeTtlMs,
      });
      try {
        await sendCode(email, code);
      } catch (error) {
        onSendError?.(error);
      }
      onEvent({ type: 'email_code.sent', emailFingerprint: await emailFingerprint(email) });
      return c.json({ ok: true as const });
    });

    app.post('/email/verify', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      const b = await body(c);
      if (!b.ok) return b.res;
      const email = readEmail(b.body?.['email']);
      const code = b.body?.['code'];
      if (!email || typeof code !== 'string' || !codeRe.test(code)) {
        return c.json({ error: 'invalid_request' as const }, 400);
      }
      const trustDevice = b.body?.['trustDevice'] !== false;
      const rawLabel = b.body?.['deviceLabel'];
      const label = typeof rawLabel === 'string' && rawLabel.length > 0 ? rawLabel.slice(0, 100) : null;

      const now = clock();
      const ipHit = await ipLimited(c, 'otp-verify', limits.verifiesPerIp, 'email_verify_ip', now);
      if (ipHit) return ipHit;

      if (breaker) {
        const [attempts, failed] = await Promise.all([
          store.readRateLimit(CB_ATTEMPTS, breaker.windowSec * SEC, now),
          store.readRateLimit(CB_FAILURES, breaker.windowSec * SEC, now),
        ]);
        if (failed.count >= breaker.minFailures && failed.count >= breaker.ratio * Math.max(attempts.count, 1)) {
          onEvent({ type: 'circuit_breaker.open', scope: 'email_verify' });
          return c.json(
            {
              error: 'temporarily_unavailable' as const,
              retryAfterSec: retryAfter(c, failed.windowStart, breaker.windowSec, now),
            },
            503,
          );
        }
        await store.hitRateLimit(CB_ATTEMPTS, breaker.windowSec * SEC, now);
      }

      const fp = await emailFingerprint(email);
      const emailKey = await sha256Hex(email);

      // Reserve a failure against the address *before* checking anything, and
      // give it back only on success. Ten concurrent guesses therefore use ten
      // reservations; the 11th is refused without being checked.
      const slot = await store.hitRateLimit(failureBucket(emailKey), failureWindowSec * SEC, now);
      if (slot.count > maxFailuresPerEmail) {
        onEvent({ type: 'rate_limited', scope: 'email_failures' });
        return c.json(
          { error: 'rate_limited' as const, retryAfterSec: retryAfter(c, slot.windowStart, failureWindowSec, now) },
          429,
        );
      }

      const invalid = async (reason: string) => {
        onEvent({ type: 'email_code.failed', emailFingerprint: fp, reason });
        if (breaker) await store.hitRateLimit(CB_FAILURES, breaker.windowSec * SEC, now);
        return c.json({ error: 'invalid_code' as const }, 401);
      };

      // Then reserve the attempt on this code: five concurrent guesses use five attempts.
      const reserved = await store.reserveEmailCodeAttempt(email, now, codeMaxAttempts);
      if (!reserved) return invalid('no_live_code');
      const derived = (await keys()).byId.get(reserved.keyId);
      const matches =
        derived !== undefined && timingSafeEqual(await hmacHex(derived.otpKey, `${email}\n${code}`), reserved.codeHash);
      if (!matches) return invalid(derived ? 'mismatch' : 'unknown_key');
      // Single use: of two correct submissions racing, one DELETE wins.
      if (!(await store.consumeEmailCode(email, reserved.codeHash))) return invalid('already_used');

      const resolved = await resolveUser(email);
      if (!checkUser(resolved)) return invalid('user_refused');
      await store.refundRateLimit(failureBucket(emailKey), slot.windowStart);
      const user: AuthUser = { ...resolved, claims: { ...resolved.claims, provider: 'email-code' } };
      onEvent({ type: 'email_code.verified', userId: user.id, emailFingerprint: fp });

      // An email code is the only thing that lifts a PIN lockout.
      const before = await store.resetLoginGuard(user.id, now);
      if (before?.lockedAt != null) onEvent({ type: 'pin.unlocked', userId: user.id });

      let device: DeviceRecord | null = null;
      let deviceToken: string | undefined;
      if (trustDevice) {
        // A repeat email login on an already-trusted device of the same
        // account reuses (and extends) it rather than registering another.
        const presented = await readDevice(c, now);
        if (presented && presented.accountId === user.id) {
          const idleExpiresAt = await store.touchDevice(presented.deviceId, now, now + deviceIdleMs);
          if (idleExpiresAt !== null) {
            device = { ...presented, lastUsedAt: now, idleExpiresAt };
            setDeviceCookie(c, presentedDeviceToken(c) as string, idleExpiresAt, now);
          }
        }
        if (!device) {
          const registered = await registerDevice(c, user, email, label, now);
          device = registered.device;
          deviceToken = registered.token;
        }
      }

      const sessionFields = await mintSession(c, user, {
        emailVerifiedAt: now,
        ...(device ? { deviceId: device.deviceId } : {}),
      });
      const pinSet = (await store.getActiveCredential(user.id, 'pin')) !== null;
      return c.json({
        ok: true as const,
        user,
        pinSet,
        device: device ? publicDevice(device) : null,
        ...(transport === 'response' && deviceToken ? { deviceToken } : {}),
        ...sessionFields,
      });
    });

    app.post('/pin', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      const session = g.session;
      if (!session) return c.json({ error: 'unauthenticated' as const }, 401);
      const now = clock();
      const verifiedAt = emailVerifiedAt(session);
      if (verifiedAt === null || now - verifiedAt > freshMs) return emailVerificationRequired(c);

      const b = await body(c);
      if (!b.ok) return b.res;
      const value = b.body?.['pin'];
      if (!isPinFormat(value)) return c.json({ error: 'invalid_pin_format' as const }, 400);
      if (defaultIsWeakPin(value, { rejectDateLike }) || extraWeak?.(value) === true) {
        return c.json({ error: 'weak_pin' as const }, 400);
      }

      const material = await pin.enroll(value, { keys: await keys() });
      const replaced = await store.replaceCredential({
        credentialId: toHex(randomBytes(16)),
        accountId: session.userId,
        type: 'pin',
        deviceId: null,
        material,
        createdAt: now,
        updatedAt: now,
        lastUsedAt: null,
      });
      await store.resetLoginGuard(session.userId, now);
      onEvent({ type: 'pin.set', userId: session.userId, replaced });

      if (replaced && revokeOthersOnChange) {
        const count = await store.revokeAllDevices(session.userId, now, sessionDeviceId(session));
        if (count > 0) onEvent({ type: 'device.revoked', userId: session.userId, count, reason: 'pin_changed' });
        // Including this session: the device that is kept still logs in again
        // with the new PIN, and a session without a device (trustDevice: false)
        // has no other way to be reached.
        await revokeAllSessions(c, session.userId, 'pin_changed');
        return c.json({ ok: true as const, signedOut: true });
      }
      return c.json({ ok: true as const });
    });

    app.get('/pin/status', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (!g.session) return c.json({ error: 'unauthenticated' as const }, 401);
      return c.json({ pinSet: (await store.getActiveCredential(g.session.userId, 'pin')) !== null });
    });

    /**
     * Order matters: everything that can be decided without PBKDF2 is decided
     * first, so an unauthenticated caller — no device, a revoked device, a
     * locked account — gets its answer without costing any CPU.
     */
    app.post('/pin/login', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      const b = await body(c);
      if (!b.ok) return b.res;
      const value = b.body?.['pin'];
      if (!isPinFormat(value)) return c.json({ error: 'invalid_pin_format' as const }, 400);

      const bot = await botRefused(c, 'pin_login');
      if (bot) return bot;

      const now = clock();
      const ipHit = await ipLimited(c, 'pin-login', limits.pinLoginsPerIp, 'pin_login_ip', now);
      if (ipHit) return ipHit;

      const device = await readDevice(c, now);
      if (!device) {
        onEvent({ type: 'pin.login.failed', reason: 'device_invalid' });
        return emailVerificationRequired(c);
      }
      const base = { userId: device.accountId, deviceId: device.deviceId };

      const credential = await store.getActiveCredential(device.accountId, 'pin');
      if (!credential) {
        onEvent({ type: 'pin.login.failed', reason: 'pin_not_set', ...base });
        return emailVerificationRequired(c);
      }

      const failedCount = await store.reserveLoginAttempt(device.accountId, pinMaxAttempts, now);
      if (failedCount === null) {
        onEvent({ type: 'pin.login.failed', reason: 'locked', ...base });
        return emailVerificationRequired(c);
      }

      const result = await pin.verify(value, credential.material, { keys: await keys() });
      if (!result.ok) {
        onEvent({ type: 'pin.login.failed', reason: 'invalid_pin', failedCount, ...base });
        if (failedCount >= pinMaxAttempts) {
          await store.lockAccount(device.accountId, pinMaxAttempts, now);
          onEvent({ type: 'pin.locked', ...base });
          return emailVerificationRequired(c);
        }
        return c.json({ error: 'invalid_pin' as const, attemptsRemaining: pinMaxAttempts - failedCount }, 401);
      }

      await store.resetLoginGuard(device.accountId, now);
      await store.markCredentialUsed(credential.credentialId, now, result.upgraded);

      const resolved = await resolveUser(device.email);
      if (!checkUser(resolved) || resolved.id !== device.accountId) {
        onEvent({ type: 'pin.login.failed', reason: 'user_unresolved', ...base });
        return emailVerificationRequired(c);
      }
      const idleExpiresAt = await store.touchDevice(device.deviceId, now, now + deviceIdleMs);
      if (idleExpiresAt === null) {
        onEvent({ type: 'pin.login.failed', reason: 'device_invalid', ...base });
        return emailVerificationRequired(c);
      }
      setDeviceCookie(c, presentedDeviceToken(c) as string, idleExpiresAt, now);

      const user: AuthUser = { ...resolved, claims: { ...resolved.claims, provider: 'device-pin' } };
      // No emailVerifiedAt: a PIN-login session can never change the PIN.
      const sessionFields = await mintSession(c, user, { deviceId: device.deviceId });
      onEvent({ type: 'pin.login.succeeded', ...base });
      return c.json({
        ok: true as const,
        user,
        device: publicDevice({ ...device, lastUsedAt: now, idleExpiresAt }),
        ...sessionFields,
      });
    });

    app.get('/devices', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (!g.session) return c.json({ error: 'unauthenticated' as const }, 401);
      return c.json({
        devices: await store.listDevices(g.session.userId, clock()),
        currentDeviceId: sessionDeviceId(g.session),
      });
    });

    /** Every device and every session of the account — this one included. */
    app.post('/devices/revoke-all', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (!g.session) return c.json({ error: 'unauthenticated' as const }, 401);
      const count = await store.revokeAllDevices(g.session.userId, clock());
      onEvent({ type: 'device.revoked', userId: g.session.userId, count, reason: 'revoke_all' });
      await revokeAllSessions(c, g.session.userId, 'revoke_all');
      clearDeviceCookie(c);
      return c.json({ ok: true as const, revoked: count });
    });

    /** Sessions minted on that device stop working on their next request (device-bound store). */
    app.post('/devices/:deviceId/revoke', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (!g.session) return c.json({ error: 'unauthenticated' as const }, 401);
      const deviceId = c.req.param('deviceId');
      const revoked = await store.revokeDevice(g.session.userId, deviceId, clock());
      if (revoked) onEvent({ type: 'device.revoked', userId: g.session.userId, deviceId, reason: 'user' });
      return c.json({ ok: true as const, revoked });
    });

    /** "Forget this device": revoke it server-side and drop the cookie; its sessions die with it. */
    app.post('/device/forget', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      const now = clock();
      const device = await readDevice(c, now);
      if (device && (await store.revokeDevice(device.accountId, device.deviceId, now))) {
        onEvent({ type: 'device.revoked', userId: device.accountId, deviceId: device.deviceId, reason: 'forget' });
      }
      clearDeviceCookie(c);
      return c.json({ ok: true as const });
    });

    /** Ends the current session (cookie or bearer). The device stays trusted. */
    app.post('/logout', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (g.session) {
        await auth.config.store.revoke(g.session.sid);
        onEvent({ type: 'session.revoked', sidFingerprint: await fingerprint(g.session.sid) });
      }
      if (transport === 'cookie') clearSessionCookies(c, auth.config);
      return c.json({ ok: true as const });
    });

    return app;
  }

  return {
    routes,

    requireFreshEmailAuth(maxAgeSec) {
      const maxAgeMs = positive(maxAgeSec, freshMs / SEC, 'requireFreshEmailAuth maxAgeSec') * SEC;
      return async (c, next) => {
        const g = await gate(c);
        if (!g.ok) {
          applyNoStore(c);
          return g.res;
        }
        if (!g.session) {
          applyNoStore(c);
          return c.json({ error: 'unauthenticated' as const }, 401);
        }
        const verifiedAt = emailVerifiedAt(g.session);
        if (verifiedAt === null || clock() - verifiedAt > maxAgeMs) {
          applyNoStore(c);
          return emailVerificationRequired(c);
        }
        c.set('user', sessionToUser(g.session));
        c.set('authSession', toSessionInfo(g.session));
        return next();
      };
    },

    listDevices(userId) {
      return store.listDevices(userId, clock());
    },

    async revokeDevice(userId, deviceId) {
      const revoked = await store.revokeDevice(userId, deviceId, clock());
      if (revoked) onEvent({ type: 'device.revoked', userId, deviceId, reason: 'app' });
      return revoked;
    },

    async revokeAllDevices(userId) {
      const count = await store.revokeAllDevices(userId, clock());
      onEvent({ type: 'device.revoked', userId, count, reason: 'app' });
      await revokeAllSessions(null, userId, 'app');
      return count;
    },

    async hasPin(userId) {
      return (await store.getActiveCredential(userId, 'pin')) !== null;
    },
  };
}
