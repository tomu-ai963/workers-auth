/**
 * Core type definitions for @tomu-ai/workers-auth.
 *
 * This module is intentionally dependency-free (no Hono, no runtime imports) so
 * that every layer can import it without dragging anything else in.
 */

// ---------------------------------------------------------------------------
// Layer 1: SessionStore
// ---------------------------------------------------------------------------

export type SubjectType = 'user' | 'service';

/** Reserved for future multi-tenant work. Not consulted by this version. */
export type SessionScope = {
  orgId?: string;
  role?: string;
};

export type Session = {
  /**
   * The raw session id. NEVER persisted — the store only ever holds
   * `sha256(sid)`. It exists on this object solely so the caller can put it in
   * a cookie right after `create()`.
   */
  sid: string;
  userId: string;
  subjectType: SubjectType;
  /** epoch ms */
  createdAt: number;
  /** epoch ms */
  lastSeenAt: number;
  /** epoch ms — sliding window; refreshed by `touch()` */
  idleExpiresAt: number;
  /** epoch ms — hard ceiling; never extended */
  absoluteExpiresAt: number;
  scope?: SessionScope;
  meta?: Record<string, unknown>;
};

export type NewSession = {
  userId: string;
  subjectType: SubjectType;
  /** Sliding inactivity window, in seconds. Required — no implicit default. */
  idleTtlSec: number;
  /** Hard lifetime, in seconds. Required — no implicit default. */
  absoluteTtlSec: number;
  scope?: SessionScope;
  meta?: Record<string, unknown>;
};

export interface SessionStore {
  /** Returns null for unknown, expired, or revoked sessions. Never throws on miss. */
  get(sid: string): Promise<Session | null>;
  create(input: NewSession): Promise<Session>;
  revoke(sid: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
  /** Extends only the idle window. Absolute expiry is never moved. */
  touch(sid: string, idleExpiresAt: number): Promise<void>;
}

/**
 * Immediate-revocation side channel for eventually-consistent primary stores
 * (i.e. KV). Keys are `sha256(sid)` hex — raw session ids never reach it.
 */
export interface RevocationList {
  isRevoked(sidHash: string): Promise<boolean>;
  /** `expiresAt` is the original session's absolute expiry (epoch ms). */
  revoke(sidHash: string, expiresAt: number): Promise<void>;
  revokeMany(entries: Array<{ sidHash: string; expiresAt: number }>): Promise<void>;
  /** Deletes tombstones whose original session would have expired anyway. */
  cleanup(now?: number): Promise<number>;
}

// ---------------------------------------------------------------------------
// Layer 2: AuthProvider
// ---------------------------------------------------------------------------

export type AuthUser = {
  id: string;
  subjectType: SubjectType;
  email?: string;
  /**
   * Provider-specific values live here and ONLY here. Do not hoist provider
   * fields onto the top level — doing so makes providers un-swappable.
   */
  claims: Record<string, unknown>;
};

export interface AuthProvider {
  readonly name: string;
  /**
   * Returns the verified subject, or null when this provider does not apply /
   * cannot verify. Must not throw for "bad credentials" — null is the answer.
   * Implementations must treat `req` as read-only (clone before reading a body).
   */
  verify(req: Request, env: unknown): Promise<AuthUser | null>;
}

// ---------------------------------------------------------------------------
// Shared config
// ---------------------------------------------------------------------------

/** Injectable clock. Defaults to `Date.now`. Exists for deterministic tests. */
export type Clock = () => number;

export type CookieConfig = {
  /** Cookie name prefix. `__Host-` (default) is the only prefix we recommend. */
  prefix?: '__Host-' | '__Secure-' | '';
  /** Base name; the session cookie becomes `${prefix}${name}`. */
  name?: string;
  /** CSRF cookie base name; becomes `${prefix}${csrfName}`. */
  csrfName?: string;
  sameSite?: 'Lax' | 'Strict' | 'None';
  /**
   * DANGER: turns off `Secure` and allows dropping the `__Host-` prefix so that
   * cookies work over plain http. Local development only — never ship this.
   */
  dangerouslyAllowInsecureCookies?: boolean;
};

export type SessionConfig = {
  /** Sliding inactivity window in seconds. Required. */
  idleTtlSec: number;
  /** Hard lifetime in seconds. Required. Must be >= idleTtlSec. */
  absoluteTtlSec: number;
  /**
   * Minimum seconds between `touch()` writes, to avoid a store write on every
   * request. Default: 60.
   */
  touchIntervalSec?: number;
};

export type CsrfConfig = {
  /**
   * Extra origins allowed to make state-changing requests. The request's own
   * origin is always allowed. Values are compared as exact origin strings.
   */
  trustedOrigins?: string[];
  /** Header carrying the double-submit token. Default: `x-csrf-token`. */
  headerName?: string;
  /**
   * DANGER: disables Origin + double-submit checking entirely. Only meaningful
   * for APIs that never authenticate via cookies.
   */
  dangerouslyDisable?: boolean;
};

export type AuthErrorCode =
  | 'unauthenticated'
  | 'csrf_failed'
  | 'invalid_request';

/** Uniform failure shape. Callers cannot distinguish *why* auth failed. */
export type AuthErrorBody = {
  error: AuthErrorCode;
};
