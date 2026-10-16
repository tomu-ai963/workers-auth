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
import type { AuthUser, Clock, Session } from '../types.js';
import {
  isPinFormat,
  isWeakPin as defaultIsWeakPin,
  pinCredential,
  type CredentialKind,
} from './credentials.js';
import { assertSecret, buildKeyRing, hmacHex, type KeyRing } from './keys.js';
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
} from './credentials.js';
export { MIN_SECRET_LENGTH } from './keys.js';
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

const SEC = 1000;
const HOUR_SEC = 60 * 60;
const DAY_SEC = 24 * HOUR_SEC;

export type DeviceAuthLimits = {
  /** Minimum gap between two codes to the same address. Default: 60. */
  resendCooldownSec?: number;
  /** Codes per address per hour. Default: 5. */
  codesPerEmailPerHour?: number;
  /** `/email/start` calls per IP per hour. Default: 20. */
  startsPerIpPerHour?: number;
  /** `/email/verify` calls per IP per hour. Default: 60. */
  verifiesPerIpPerHour?: number;
  /** `/pin/login` calls per IP per hour. Default: 60. */
  pinLoginsPerIpPerHour?: number;
};

export type DeviceAuthOptions = {
  auth: Auth;
  store: DeviceAuthStore;
  /**
   * The one secret everything is derived from (HKDF): the email-code HMAC key
   * and the PIN pepper. At least 32 characters. Keep it in `wrangler secret`.
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
  /** Delivers the code. Called for every valid-looking address, known or not. */
  sendCode: (email: string, code: string) => Promise<void>;
  /** Delivery failures go here rather than into the response (that would be an oracle). */
  onSendError?: (error: unknown) => void;
  /**
   * Maps a verified address to the account. Default: id = email. Return null
   * to refuse (e.g. sign-up closed). Also called on every PIN login with the
   * address the device was registered under; it must return the same id.
   */
  resolveUser?: (email: string) => AuthUser | null | Promise<AuthUser | null>;
  /** Base name of the device cookie (prefix follows the session cookie). Default: `device`. */
  deviceCookieName?: string;
  device?: {
    /** Extended by every PIN login. Default: 90 days. */
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
    /** Revoke the account's other trusted devices when an existing PIN is replaced. Default: false. */
    revokeOtherDevicesOnChange?: boolean;
  };
  emailCode?: {
    /** Default: 600 (10 minutes). */
    ttlSec?: number;
    /** Wrong guesses allowed per code. Default: 5. */
    maxAttempts?: number;
  };
  /** How recent an email verification `POST /pin` requires. Default: 600. */
  freshEmailAuthSec?: number;
  /** `transport: 'response'` only: bearer session lifetime, no sliding. Default: 43,200 (12 hours). */
  bearerSessionTtlSec?: number;
  limits?: DeviceAuthLimits;
  /**
   * The client IP for per-IP limits. Default: `CF-Connecting-IP`, which
   * Cloudflare always sets. When this returns null, per-IP limits are skipped.
   */
  getClientIp?: (req: Request) => string | null;
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
  revokeDevice(userId: string, deviceId: string): Promise<boolean>;
  revokeAllDevices(userId: string): Promise<number>;
  hasPin(userId: string): Promise<boolean>;
};

const MAX_EMAIL_LENGTH = 320;
const CODE_RE = /^\d{6}$/;
const DEVICE_TOKEN_RE = /^([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/;
const COOKIE_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function looksLikeEmail(email: string): boolean {
  return email.length > 2 && email.length <= MAX_EMAIL_LENGTH && /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(email);
}

/** Uniform 6-digit code: rejection sampling, so no residue is more likely than another. */
export function generateEmailCode(): string {
  const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    const value = buf[0] as number;
    if (value < limit) return String(value % 1_000_000).padStart(6, '0');
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

async function readJson(c: Context): Promise<Record<string, unknown> | null> {
  try {
    const body = (await c.req.raw.clone().json()) as unknown;
    return body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
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

  const deviceIdleMs = positive(options.device?.idleTtlSec, 90 * DAY_SEC, 'device.idleTtlSec') * SEC;
  const deviceAbsoluteMs = positive(options.device?.absoluteTtlSec, 365 * DAY_SEC, 'device.absoluteTtlSec') * SEC;
  if (deviceAbsoluteMs < deviceIdleMs) {
    throw new TypeError('deviceAuth: device.absoluteTtlSec must be >= device.idleTtlSec');
  }
  const pinMaxAttempts = positive(options.pin?.maxAttempts, 3, 'pin.maxAttempts', true);
  const codeTtlMs = positive(options.emailCode?.ttlSec, 600, 'emailCode.ttlSec') * SEC;
  const codeMaxAttempts = positive(options.emailCode?.maxAttempts, 5, 'emailCode.maxAttempts', true);
  const freshMs = positive(options.freshEmailAuthSec, 600, 'freshEmailAuthSec') * SEC;
  const bearerTtlSec = positive(options.bearerSessionTtlSec, 12 * HOUR_SEC, 'bearerSessionTtlSec');
  const limits = {
    cooldownSec: positive(options.limits?.resendCooldownSec, 60, 'limits.resendCooldownSec'),
    perEmail: positive(options.limits?.codesPerEmailPerHour, 5, 'limits.codesPerEmailPerHour', true),
    startsPerIp: positive(options.limits?.startsPerIpPerHour, 20, 'limits.startsPerIpPerHour', true),
    verifiesPerIp: positive(options.limits?.verifiesPerIpPerHour, 60, 'limits.verifiesPerIpPerHour', true),
    pinLoginsPerIp: positive(options.limits?.pinLoginsPerIpPerHour, 60, 'limits.pinLoginsPerIpPerHour', true),
  };
  const pin: CredentialKind<string> = pinCredential({ iterations: options.pin?.iterations });
  const extraWeak = options.pin?.isWeakPin;
  const revokeOthersOnChange = options.pin?.revokeOtherDevicesOnChange === true;
  const getClientIp = options.getClientIp ?? ((req: Request) => req.headers.get('cf-connecting-ip'));
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
    const retryAfterSec = Math.max(1, Math.ceil((windowStart + windowSec * SEC - now) / SEC));
    onEvent({ type: 'rate_limited', scope });
    c.header('retry-after', String(retryAfterSec));
    return c.json({ error: 'rate_limited' as const, retryAfterSec }, 429);
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
  async function mintSession(
    c: Context,
    user: AuthUser,
    authMeta: { emailVerifiedAt?: number; deviceId?: string },
  ): Promise<Record<string, unknown>> {
    if (transport === 'cookie') {
      await auth.createSession(c, user, { authMeta });
      return {};
    }
    const session = await auth.createSession(c, user, {
      transport: 'bearer',
      ttl: { idleTtlSec: bearerTtlSec, absoluteTtlSec: bearerTtlSec },
      authMeta,
    });
    return { sessionToken: bearerSessionToken(session.sid), sessionExpiresAt: session.absoluteExpiresAt };
  }

  function checkUser(user: AuthUser | null): user is AuthUser {
    return !!user && typeof user.rateLimitId === 'string' && user.rateLimitId.length > 0;
  }

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
      const body = await readJson(c);
      const email = normalizeEmail(typeof body?.['email'] === 'string' ? body['email'] : '');
      if (!looksLikeEmail(email)) return c.json({ error: 'invalid_request' as const }, 400);

      const now = clock();
      const ip = getClientIp(c.req.raw);
      if (ip) {
        const hit = await rateLimited(c, `otp-start:ip:${ip}`, HOUR_SEC, limits.startsPerIp, 'email_start_ip', now);
        if (hit) return hit;
      }
      const emailKey = await sha256Hex(email);
      const cooled = await rateLimited(c, `otp-cool:${emailKey}`, limits.cooldownSec, 1, 'email_cooldown', now);
      if (cooled) return cooled;
      const capped = await rateLimited(c, `otp-email:${emailKey}`, HOUR_SEC, limits.perEmail, 'email_hourly', now);
      if (capped) return capped;

      const ring = await keys();
      const code = generateEmailCode();
      await store.putEmailCode({
        email,
        codeHash: await hmacHex(ring.current.otpKey, `${email}\n${code}`),
        keyId: ring.current.keyId,
        expiresAt: now + codeTtlMs,
        createdAt: now,
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
      const body = await readJson(c);
      const email = normalizeEmail(typeof body?.['email'] === 'string' ? body['email'] : '');
      const code = body?.['code'];
      if (!looksLikeEmail(email) || typeof code !== 'string' || !CODE_RE.test(code)) {
        return c.json({ error: 'invalid_request' as const }, 400);
      }
      const trustDevice = body?.['trustDevice'] !== false;
      const rawLabel = body?.['deviceLabel'];
      const label = typeof rawLabel === 'string' && rawLabel.length > 0 ? rawLabel.slice(0, 100) : null;

      const now = clock();
      const ip = getClientIp(c.req.raw);
      if (ip) {
        const hit = await rateLimited(c, `otp-verify:ip:${ip}`, HOUR_SEC, limits.verifiesPerIp, 'email_verify_ip', now);
        if (hit) return hit;
      }

      const fp = await emailFingerprint(email);
      const invalid = (reason: string) => {
        onEvent({ type: 'email_code.failed', emailFingerprint: fp, reason });
        return c.json({ error: 'invalid_code' as const }, 401);
      };

      // Reserve the attempt first: five concurrent guesses use five attempts.
      const reserved = await store.reserveEmailCodeAttempt(email, now, codeMaxAttempts);
      if (!reserved) return invalid('no_live_code');
      const derived = (await keys()).byId.get(reserved.keyId);
      const matches =
        derived !== undefined && timingSafeEqual(await hmacHex(derived.otpKey, `${email}\n${code}`), reserved.codeHash);
      if (!matches) {
        if (reserved.attempts >= codeMaxAttempts) await store.deleteEmailCode(email);
        return invalid(derived ? 'mismatch' : 'unknown_key');
      }
      // Single use: of two correct submissions racing, one DELETE wins.
      if (!(await store.consumeEmailCode(email, reserved.codeHash))) return invalid('already_used');

      const resolved = await resolveUser(email);
      if (!checkUser(resolved)) return invalid('user_refused');
      const user: AuthUser = { ...resolved, claims: { ...resolved.claims, provider: 'email-code' } };
      onEvent({ type: 'email_code.verified', userId: user.id, emailFingerprint: fp });

      // An email code is the only thing that lifts a PIN lockout.
      const before = await store.resetLoginGuard(user.id, now);
      if (before?.lockedAt != null) onEvent({ type: 'pin.unlocked', userId: user.id });

      let device: DeviceRecord | null = null;
      let deviceToken: string | undefined;
      if (trustDevice) {
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

      const body = await readJson(c);
      const value = body?.['pin'];
      if (!isPinFormat(value)) return c.json({ error: 'invalid_pin_format' as const }, 400);
      if (defaultIsWeakPin(value) || extraWeak?.(value) === true) {
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
      const body = await readJson(c);
      const value = body?.['pin'];
      if (!isPinFormat(value)) return c.json({ error: 'invalid_pin_format' as const }, 400);

      const now = clock();
      const ip = getClientIp(c.req.raw);
      if (ip) {
        const hit = await rateLimited(c, `pin-login:ip:${ip}`, HOUR_SEC, limits.pinLoginsPerIp, 'pin_login_ip', now);
        if (hit) return hit;
      }

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

    app.post('/devices/revoke-all', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (!g.session) return c.json({ error: 'unauthenticated' as const }, 401);
      const count = await store.revokeAllDevices(g.session.userId, clock());
      onEvent({ type: 'device.revoked', userId: g.session.userId, count, reason: 'revoke_all' });
      clearDeviceCookie(c);
      return c.json({ ok: true as const, revoked: count });
    });

    app.post('/devices/:deviceId/revoke', async (c) => {
      const g = await gate(c);
      if (!g.ok) return g.res;
      if (!g.session) return c.json({ error: 'unauthenticated' as const }, 401);
      const deviceId = c.req.param('deviceId');
      const revoked = await store.revokeDevice(g.session.userId, deviceId, clock());
      if (revoked) onEvent({ type: 'device.revoked', userId: g.session.userId, deviceId, reason: 'user' });
      return c.json({ ok: true as const, revoked });
    });

    /** "Forget this device": revoke it server-side and drop the cookie. */
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
      return count;
    },

    async hasPin(userId) {
      return (await store.getActiveCredential(userId, 'pin')) !== null;
    },
  };
}
