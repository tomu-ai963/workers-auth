/**
 * Magic-link provider.
 *
 * This module does NOT send email. You inject `sendToken`; the SDK stays free
 * of Resend/SES/etc. and the subpath split keeps its meaning.
 *
 * Enumeration resistance: `start()` performs the exact same work for every
 * address — generate, hash, store, hand off to `sendToken` — and always returns
 * the same value. Send failures are routed to `onSendError` instead of
 * surfacing, because "this address errored" is itself an oracle.
 */

import { randomToken, sha256Hex } from '../crypto.js';
import type { AuthProvider, AuthUser, Clock } from '../types.js';

export type MagicLinkRecord = {
  email: string;
  /** epoch ms */
  expiresAt: number;
};

/** Optional on `MagicLinkStore`; only `d1MagicLinkStore` implements it. */
export interface MagicLinkStoreCleanup {
  /** Deletes expired, never-consumed tokens. Returns the number removed. */
  cleanup(now?: number): Promise<number>;
}

export interface MagicLinkStore {
  /**
   * Whether `take()` is a single indivisible operation.
   *
   * This is the entire security property of a magic link. A store that reads
   * and then deletes — however consistent the underlying storage — lets two
   * concurrent requests both observe the same token, so the link is replayable.
   * `magicLink()` refuses a store that reports `false`.
   */
  readonly atomicTake: boolean;
  put(tokenHash: string, record: MagicLinkRecord): Promise<void>;
  /** Consume the token. Must delete it, whether or not it turns out to be valid. */
  take(tokenHash: string): Promise<MagicLinkRecord | null>;
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export type KvMagicLinkStoreOptions = { prefix?: string; clock?: Clock };

/**
 * KV token store — REPLAYABLE, and `magicLink()` rejects it by default.
 *
 * KV has no atomic read-and-delete, so `take()` is a `get` followed by a
 * `delete`. Two requests that arrive together both see the token and both log
 * in; this is a plain interleaving, not an eventual-consistency artefact, and
 * it reproduces on a strongly consistent local emulator. An email scanner that
 * pre-fetches the link, a double click, or an attacker racing the victim all
 * trigger it.
 *
 * Use {@link d1MagicLinkStore}.
 */
export function kvMagicLinkStore(
  kv: KVNamespace,
  options: KvMagicLinkStoreOptions = {},
): MagicLinkStore {
  const prefix = options.prefix ?? 'mlt:';
  const now: Clock = options.clock ?? Date.now;

  return {
    atomicTake: false,
    async put(tokenHash, record) {
      const ttl = Math.max(60, Math.ceil((record.expiresAt - now()) / 1000));
      await kv.put(`${prefix}${tokenHash}`, JSON.stringify(record), { expirationTtl: ttl });
    },
    async take(tokenHash) {
      const key = `${prefix}${tokenHash}`;
      const record = await kv.get<MagicLinkRecord>(key, 'json');
      await kv.delete(key);
      return record ?? null;
    },
  };
}

export type D1MagicLinkStoreOptions = { table?: string; clock?: Clock };

/**
 * D1 token store. `DELETE ... RETURNING` is one statement: the row is removed
 * and returned indivisibly, so exactly one of two racing requests can get it.
 * That — not D1's consistency model — is what makes single use hold.
 */
export function d1MagicLinkStore(
  db: D1Database,
  options: D1MagicLinkStoreOptions = {},
): MagicLinkStore & MagicLinkStoreCleanup {
  const table = options.table ?? 'auth_magic_link_tokens';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) {
    throw new TypeError(`d1MagicLinkStore.table: ${JSON.stringify(table)} is not a valid SQL identifier`);
  }
  const now: Clock = options.clock ?? Date.now;

  return {
    atomicTake: true,
    async put(tokenHash, record) {
      await db
        .prepare(
          `INSERT INTO ${table} (token_hash, email, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)`,
        )
        .bind(tokenHash, record.email, record.expiresAt, now())
        .run();
    },
    async take(tokenHash) {
      const row = await db
        .prepare(`DELETE FROM ${table} WHERE token_hash = ?1 RETURNING email, expires_at`)
        .bind(tokenHash)
        .first<{ email: string; expires_at: number }>();
      return row ? { email: row.email, expiresAt: row.expires_at } : null;
    },
    /**
     * Only expired tokens ever accumulate here: a consumed one is deleted by
     * `take()` in the same statement that reads it. Safe to run from a cron
     * trigger.
     */
    async cleanup(at?: number): Promise<number> {
      const result = await db
        .prepare(`DELETE FROM ${table} WHERE expires_at <= ?1`)
        .bind(at ?? now())
        .run();
      return result.meta.changes ?? 0;
    },
  };
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export type MagicLinkOptions = {
  store: MagicLinkStore;
  /**
   * Delivers the raw token to the address. Called for every request, including
   * addresses you do not recognise — swallow that case inside your own sender
   * rather than branching before it, or the timing gives the answer away.
   */
  sendToken: (email: string, token: string) => Promise<void>;
  /** Token lifetime. Default: 900 (15 minutes). */
  ttlSec?: number;
  /**
   * Read the token from `?token=` as well as from the header and body.
   *
   * A URL-borne credential leaks through Referer headers, browser history,
   * access logs and shared inboxes, so a provider configured this way is
   * marked `callbackOnly` and may only be listed in `callbackProviders` —
   * `createAuth()` throws if it appears in `providers`. That is what stops
   * `GET /api/anything?token=…` from authenticating, and stops an arbitrary
   * request from burning the token.
   */
  allowTokenInQuery?: boolean;
  /**
   * Accept a store whose `take()` is not atomic, making links replayable.
   * There is no good reason to set this outside a throwaway prototype.
   */
  dangerouslyAllowReplayableTokens?: boolean;
  /** Where to find the token on an incoming request. */
  getToken?: (req: Request) => string | null | Promise<string | null>;
  /** Map a verified address to your own user record. Default: id = email. */
  resolveUser?: (email: string) => AuthUser | null | Promise<AuthUser | null>;
  /** Observability hook for delivery failures. Never receives the raw token. */
  onSendError?: (error: unknown) => void;
  clock?: Clock;
  name?: string;
};

export interface MagicLinkProvider extends AuthProvider {
  /**
   * Issues and delivers a token. Always resolves to the same value regardless
   * of whether the address exists, is malformed downstream, or delivery failed.
   */
  start(email: string): Promise<{ ok: true }>;
}

const MAX_EMAIL_LENGTH = 320;

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function looksLikeEmail(email: string): boolean {
  return email.length > 2 && email.length <= MAX_EMAIL_LENGTH && /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(email);
}

/**
 * Header and body only. Reading `?token=` is opt-in via `allowTokenInQuery`,
 * because a token in the URL would otherwise be honoured — and consumed — by
 * every route the provider is mounted on.
 */
function makeGetToken(allowQuery: boolean) {
  return async function getToken(req: Request): Promise<string | null> {
    if (allowQuery) {
      const fromQuery = new URL(req.url).searchParams.get('token');
      if (fromQuery) return fromQuery;
    }

    const fromHeader = req.headers.get('x-magic-token');
    if (fromHeader) return fromHeader;

    const contentType = req.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      try {
        const body = (await req.clone().json()) as { token?: unknown };
        if (body && typeof body.token === 'string') return body.token;
      } catch {
        return null;
      }
    }
    return null;
  };
}

export function magicLink(options: MagicLinkOptions): MagicLinkProvider {
  const {
    store,
    sendToken,
    ttlSec = 900,
    allowTokenInQuery = false,
    dangerouslyAllowReplayableTokens = false,
    getToken = makeGetToken(allowTokenInQuery),
    resolveUser,
    onSendError,
    clock = Date.now,
    name = 'magic-link',
  } = options;

  if (typeof sendToken !== 'function') {
    throw new TypeError('magicLink: sendToken is required (this SDK does not send email)');
  }
  if (!Number.isFinite(ttlSec) || ttlSec <= 0) {
    throw new TypeError('magicLink: ttlSec must be a positive number of seconds');
  }
  if (!store || typeof store.take !== 'function') {
    throw new TypeError('magicLink: a MagicLinkStore is required');
  }
  if (!store.atomicTake && !dangerouslyAllowReplayableTokens) {
    throw new TypeError(
      'magicLink: this store cannot consume a token atomically, so its links are replayable — ' +
        'two concurrent requests can both log in with the same token. Use d1MagicLinkStore(), ' +
        'or set dangerouslyAllowReplayableTokens: true if you genuinely accept that.',
    );
  }

  return {
    name,
    callbackOnly: allowTokenInQuery,

    async start(rawEmail: string): Promise<{ ok: true }> {
      const email = normalizeEmail(String(rawEmail ?? ''));
      if (!looksLikeEmail(email)) {
        // Malformed input is a client bug, not an account oracle.
        throw new TypeError('magicLink: a syntactically valid email address is required');
      }

      const token = randomToken();
      const tokenHash = await sha256Hex(token);
      await store.put(tokenHash, { email, expiresAt: clock() + ttlSec * 1000 });

      try {
        await sendToken(email, token);
      } catch (error) {
        onSendError?.(error);
      }
      return { ok: true };
    },

    async verify(req: Request): Promise<AuthUser | null> {
      const token = await getToken(req);
      if (!token || token.length > 512) return null;

      const tokenHash = await sha256Hex(token);
      const record = await store.take(tokenHash);
      if (!record) return null;
      if (clock() >= record.expiresAt) return null;

      if (resolveUser) {
        const user = await resolveUser(record.email);
        if (!user) return null;
        return { ...user, claims: { ...user.claims, provider: name } };
      }

      return {
        id: record.email,
        subjectType: 'user',
        email: record.email,
        claims: { email: record.email, provider: name },
      };
    },
  };
}
