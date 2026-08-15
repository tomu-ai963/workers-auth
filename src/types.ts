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
   * `sha256(sid)`.
   *
   * It exists on this object solely so the caller can put it in a cookie right
   * after `create()`. It is stripped before the session reaches application
   * code (see {@link SessionInfo}), so there is no route by which it can be
   * logged or serialised into a response by accident.
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

/**
 * A session as application code sees it: everything except the credential.
 * This is what `c.get('authSession')` holds.
 */
export type SessionInfo = Omit<Session, 'sid'>;

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
  /**
   * Whether `revokeAllForUser()` on this store can actually guarantee "log
   * out everywhere," as opposed to being a no-op.
   *
   * A store that cannot guarantee it reliably (e.g. a KV-only store with no
   * {@link RevocationList} attached) MUST refuse that configuration at
   * *construction* time rather than let the gap go unnoticed until
   * `revokeAllForUser()` is actually called — see `kvSessionStore`'s
   * `allowUnrevocableSessions`. By the time a store exists, this flag is
   * already decided; it exists so a caller can check it — before calling
   * `revokeAllForUser()`, or while building an audit trail — rather than
   * only learning the answer from documentation or from the fact that
   * nothing visibly happened.
   */
  readonly canRevokeAllForUser: boolean;
  /**
   * Revokes every session of a user.
   *
   * When `canRevokeAllForUser` is `false`, this resolves without revoking
   * anything — the caller already accepted that possibility by choosing a
   * construction that sets the flag to `false`, so there is nothing left to
   * decide at call time. Implementations MUST NOT throw here for a
   * configuration that construction already accepted: construction is where
   * that decision belongs, not the moment "log out everywhere" is actually
   * needed (typically incident response — the worst time to discover a
   * missing dependency for the first time).
   */
  revokeAllForUser(userId: string): Promise<void>;
  /** Extends only the idle window. Absolute expiry is never moved. */
  touch(sid: string, idleExpiresAt: number): Promise<void>;
}

/** Everything needed to decide whether a session has been revoked. */
export type RevocationQuery = {
  /** `sha256(sid)` hex. Raw session ids never reach the revocation list. */
  sidHash: string;
  /** Checked against the user-level revocation marker. */
  userId: string;
  /** Session creation time (epoch ms), compared to `revoked_before`. */
  createdAt: number;
};

/**
 * Strongly-consistent revocation side channel for stores that cannot revoke
 * reliably on their own (i.e. KV).
 *
 * It answers two questions in one round trip: was *this* session revoked, and
 * was *every* session of this user revoked before it was created.
 */
export interface RevocationList {
  isRevoked(query: RevocationQuery): Promise<boolean>;
  /** `expiresAt` is the original session's absolute expiry (epoch ms). */
  revoke(sidHash: string, expiresAt: number): Promise<void>;
  revokeMany(entries: Array<{ sidHash: string; expiresAt: number }>): Promise<void>;
  /**
   * Invalidates every session of `userId` created before `revokedBefore`
   * (epoch ms). Unlike per-session tombstones this needs no enumeration, so it
   * cannot miss a session that a listing has not caught up with yet.
   */
  revokeUser(userId: string, revokedBefore: number): Promise<void>;
  /** Deletes records that can no longer affect any live session. */
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
   * Set when the provider reads its credential out of the URL. Such providers
   * may only be listed in `callbackProviders`; `createAuth` throws if one shows
   * up in `providers`, because a URL-borne credential must not be accepted on
   * every route.
   */
  readonly callbackOnly?: boolean;
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
