/**
 * Service-to-service API keys.
 *
 * Key format: `tk_<env>_<keyId>.<secret>`
 *   - `keyId` is a public lookup handle (hex, never secret)
 *   - `secret` is 256 bits of randomness, stored only as SHA-256 hex
 *
 * Verification always hashes the presented secret and always runs a
 * constant-time comparison — including for unknown key ids, so "no such key"
 * and "wrong secret" take the same path.
 */

import { randomToken, sha256Hex, timingSafeEqual } from '../crypto.js';
import type { AuthProvider, AuthUser, Clock } from '../types.js';

export type ApiKeyRecord = {
  keyId: string;
  env: string;
  /** sha256(secret), hex. */
  secretHash: string;
  /** The principal this key acts as. */
  subjectId: string;
  label?: string;
  claims?: Record<string, unknown>;
  createdAt: number;
  /** epoch ms, or null for no expiry. */
  expiresAt?: number | null;
  lastUsedAt?: number | null;
  revokedAt?: number | null;
};

export interface ApiKeyStore {
  findById(keyId: string): Promise<ApiKeyRecord | null>;
  put(record: ApiKeyRecord): Promise<void>;
  revoke(keyId: string): Promise<void>;
  touch?(keyId: string, at: number): Promise<void>;
}

const KEY_RE = /^tk_([a-z0-9]{1,16})_([a-f0-9]{16,64})\.([A-Za-z0-9_-]{20,256})$/;

/** A hash that no secret produces, used to keep the unknown-key path equal cost. */
const DUMMY_HASH = '0'.repeat(64);

export type ParsedApiKey = { env: string; keyId: string; secret: string };

export function parseApiKey(value: string): ParsedApiKey | null {
  const match = KEY_RE.exec(value);
  if (!match) return null;
  return { env: match[1] as string, keyId: match[2] as string, secret: match[3] as string };
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export type KvApiKeyStoreOptions = { prefix?: string };

export function kvApiKeyStore(kv: KVNamespace, options: KvApiKeyStoreOptions = {}): ApiKeyStore {
  const prefix = options.prefix ?? 'apikey:';
  return {
    async findById(keyId) {
      return (await kv.get<ApiKeyRecord>(`${prefix}${keyId}`, 'json')) ?? null;
    },
    async put(record) {
      await kv.put(`${prefix}${record.keyId}`, JSON.stringify(record));
    },
    async revoke(keyId) {
      const existing = await kv.get<ApiKeyRecord>(`${prefix}${keyId}`, 'json');
      if (!existing) return;
      await kv.put(`${prefix}${keyId}`, JSON.stringify({ ...existing, revokedAt: Date.now() }));
    },
  };
}

export type D1ApiKeyStoreOptions = { table?: string; clock?: Clock };

export function d1ApiKeyStore(db: D1Database, options: D1ApiKeyStoreOptions = {}): ApiKeyStore {
  const table = options.table ?? 'auth_api_keys';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) {
    throw new TypeError(`d1ApiKeyStore.table: ${JSON.stringify(table)} is not a valid SQL identifier`);
  }
  const now: Clock = options.clock ?? Date.now;

  type Row = {
    key_id: string;
    env: string;
    secret_hash: string;
    subject_id: string;
    label: string | null;
    claims: string | null;
    created_at: number;
    expires_at: number | null;
    last_used_at: number | null;
    revoked_at: number | null;
  };

  return {
    async findById(keyId) {
      const row = await db.prepare(`SELECT * FROM ${table} WHERE key_id = ?1`).bind(keyId).first<Row>();
      if (!row) return null;
      let claims: Record<string, unknown> | undefined;
      if (row.claims) {
        try {
          claims = JSON.parse(row.claims) as Record<string, unknown>;
        } catch {
          claims = undefined;
        }
      }
      return {
        keyId: row.key_id,
        env: row.env,
        secretHash: row.secret_hash,
        subjectId: row.subject_id,
        ...(row.label ? { label: row.label } : {}),
        ...(claims ? { claims } : {}),
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        lastUsedAt: row.last_used_at,
        revokedAt: row.revoked_at,
      };
    },
    async put(record) {
      await db
        .prepare(
          `INSERT INTO ${table}
             (key_id, env, secret_hash, subject_id, label, claims, created_at, expires_at, last_used_at, revoked_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
           ON CONFLICT(key_id) DO UPDATE SET
             secret_hash = excluded.secret_hash,
             subject_id  = excluded.subject_id,
             label       = excluded.label,
             claims      = excluded.claims,
             expires_at  = excluded.expires_at,
             revoked_at  = excluded.revoked_at`,
        )
        .bind(
          record.keyId,
          record.env,
          record.secretHash,
          record.subjectId,
          record.label ?? null,
          record.claims ? JSON.stringify(record.claims) : null,
          record.createdAt,
          record.expiresAt ?? null,
          record.lastUsedAt ?? null,
          record.revokedAt ?? null,
        )
        .run();
    },
    async revoke(keyId) {
      await db
        .prepare(`UPDATE ${table} SET revoked_at = ?2 WHERE key_id = ?1 AND revoked_at IS NULL`)
        .bind(keyId, now())
        .run();
    },
    async touch(keyId, at) {
      await db.prepare(`UPDATE ${table} SET last_used_at = ?2 WHERE key_id = ?1`).bind(keyId, at).run();
    },
  };
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

export type IssueApiKeyInput = {
  store: ApiKeyStore;
  /** Environment tag baked into the key, e.g. `live` / `test`. */
  env: string;
  subjectId: string;
  label?: string;
  claims?: Record<string, unknown>;
  /** Optional lifetime in seconds. */
  ttlSec?: number;
  clock?: Clock;
};

export type IssuedApiKey = {
  /** The full key. Shown once, at issuance. Never recoverable afterwards. */
  key: string;
  keyId: string;
  record: ApiKeyRecord;
};

export async function issueApiKey(input: IssueApiKeyInput): Promise<IssuedApiKey> {
  const { store, env, subjectId, label, claims, ttlSec } = input;
  const now: Clock = input.clock ?? Date.now;

  if (!/^[a-z0-9]{1,16}$/.test(env)) {
    throw new TypeError('issueApiKey: env must be 1-16 lowercase alphanumerics (e.g. "live")');
  }
  if (!subjectId) throw new TypeError('issueApiKey: subjectId is required');

  const keyIdBytes = new Uint8Array(12);
  crypto.getRandomValues(keyIdBytes);
  const keyId = Array.from(keyIdBytes, (b) => b.toString(16).padStart(2, '0')).join('');

  const secret = randomToken();
  const secretHash = await sha256Hex(secret);
  const at = now();

  const record: ApiKeyRecord = {
    keyId,
    env,
    secretHash,
    subjectId,
    ...(label ? { label } : {}),
    ...(claims ? { claims } : {}),
    createdAt: at,
    expiresAt: ttlSec ? at + ttlSec * 1000 : null,
    lastUsedAt: null,
    revokedAt: null,
  };
  await store.put(record);

  return { key: `tk_${env}_${keyId}.${secret}`, keyId, record };
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export type ApiKeyOptions = {
  store: ApiKeyStore;
  /** If set, keys minted for a different environment are rejected. */
  env?: string;
  /** Where to read the key from. Default: `Authorization: Bearer` then `x-api-key`. */
  getKey?: (req: Request) => string | null;
  /** Write `last_used_at` on every successful verify. Costs one extra write. */
  trackLastUsed?: boolean;
  clock?: Clock;
  name?: string;
};

function defaultGetKey(req: Request): string | null {
  const auth = req.headers.get('authorization');
  if (auth) {
    const match = /^Bearer\s+(\S+)$/i.exec(auth.trim());
    if (match?.[1]) return match[1];
  }
  return req.headers.get('x-api-key');
}

export function apiKey(options: ApiKeyOptions): AuthProvider {
  const {
    store,
    env,
    getKey = defaultGetKey,
    trackLastUsed = false,
    clock = Date.now,
    name = 'api-key',
  } = options;

  return {
    name,

    async verify(req: Request): Promise<AuthUser | null> {
      const raw = getKey(req);
      if (!raw) return null;

      const parsed = parseApiKey(raw);
      if (!parsed) return null;

      const record = await store.findById(parsed.keyId);
      // Hash and compare unconditionally so an unknown key id costs the same.
      const presented = await sha256Hex(parsed.secret);
      const matches = timingSafeEqual(presented, record?.secretHash ?? DUMMY_HASH);

      if (!record || !matches) return null;
      if (record.revokedAt) return null;

      const at = clock();
      if (record.expiresAt && at >= record.expiresAt) return null;
      if (record.env !== parsed.env) return null;
      if (env !== undefined && record.env !== env) return null;

      if (trackLastUsed && store.touch) {
        try {
          await store.touch(record.keyId, at);
        } catch {
          // Usage tracking must never fail a valid request.
        }
      }

      return {
        id: record.subjectId,
        subjectType: 'service',
        claims: {
          ...(record.claims ?? {}),
          keyId: record.keyId,
          env: record.env,
          ...(record.label ? { label: record.label } : {}),
          provider: name,
        },
      };
    },
  };
}
