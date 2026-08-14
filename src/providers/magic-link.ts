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

export interface MagicLinkStore {
  put(tokenHash: string, record: MagicLinkRecord): Promise<void>;
  /** Consume the token. Must delete it, whether or not it turns out to be valid. */
  take(tokenHash: string): Promise<MagicLinkRecord | null>;
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export type KvMagicLinkStoreOptions = { prefix?: string; clock?: Clock };

/**
 * KV token store. Convenient, but KV has no atomic read-and-delete: two
 * requests that race on the same token can both observe it. Use
 * {@link d1MagicLinkStore} when strict single-use matters.
 */
export function kvMagicLinkStore(
  kv: KVNamespace,
  options: KvMagicLinkStoreOptions = {},
): MagicLinkStore {
  const prefix = options.prefix ?? 'mlt:';
  const now: Clock = options.clock ?? Date.now;

  return {
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

/** D1 token store. `DELETE ... RETURNING` makes single-use atomic. */
export function d1MagicLinkStore(
  db: D1Database,
  options: D1MagicLinkStoreOptions = {},
): MagicLinkStore {
  const table = options.table ?? 'auth_magic_link_tokens';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) {
    throw new TypeError(`d1MagicLinkStore.table: ${JSON.stringify(table)} is not a valid SQL identifier`);
  }
  const now: Clock = options.clock ?? Date.now;

  return {
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

async function defaultGetToken(req: Request): Promise<string | null> {
  const url = new URL(req.url);
  const fromQuery = url.searchParams.get('token');
  if (fromQuery) return fromQuery;

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
}

export function magicLink(options: MagicLinkOptions): MagicLinkProvider {
  const {
    store,
    sendToken,
    ttlSec = 900,
    getToken = defaultGetToken,
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

  return {
    name,

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
