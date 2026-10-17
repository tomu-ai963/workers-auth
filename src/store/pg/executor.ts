/**
 * The one thing the Postgres stores need from a driver.
 *
 * Structural on purpose: this package depends on no Postgres driver. The app
 * passes an object of this shape built from the driver it already uses — the
 * README has short adapters for `@neondatabase/serverless` (HTTP, the default)
 * and for `pg` behind Hyperdrive.
 *
 * Requirements on what is behind it, all relied on for the limits to hold:
 *   - READ COMMITTED (Postgres' default). Each `query()` is one statement in
 *     its own transaction (autocommit).
 *   - `transaction()` runs the statements in order in ONE transaction and
 *     commits only if all succeed — non-interactive, which is all the stores
 *     need (Neon HTTP's `sql.transaction([...])`, or BEGIN … COMMIT on a client).
 *   - The primary, read-write endpoint: no read replica, and no query cache
 *     (a Hyperdrive configuration must be created with `--caching-disabled`).
 *     A stale read lets a revoked device or session through.
 *   - Errors carry the SQLSTATE in `code` (both drivers do).
 *   - `rowCount` is a number (see PgQueryResult).
 *   - Used in autocommit, never inside a transaction the app opened: a
 *     rollback there would also undo the failure reservations, giving PIN and
 *     code guesses back. And one connection per request — a `pg` Client is
 *     not shared across requests.
 */

export type PgRow = Record<string, unknown>;

export type PgQueryResult<R extends PgRow = PgRow> = {
  rows: R[];
  /**
   * Rows affected (INSERT/UPDATE/DELETE) or returned (SELECT), as a number.
   * Required: an adapter must not pass a driver's null through. The stores
   * decide anything security-relevant from RETURNING rows, and refuse a
   * non-numeric count where they still read one (cleanup totals).
   */
  rowCount: number;
};

export type PgStatement = { text: string; params: readonly unknown[] };

export interface PgExecutor {
  query<R extends PgRow = PgRow>(text: string, params: readonly unknown[]): Promise<PgQueryResult<R>>;
  transaction(statements: readonly PgStatement[]): Promise<PgQueryResult[]>;
}

const PG_IDENTIFIER_RE = /^[a-z_][a-z0-9_]{0,62}$/;

/**
 * The `schema` option is interpolated into SQL (an identifier cannot be a bind
 * parameter), so only a plain lower-case Postgres identifier of at most 63
 * bytes is accepted: no quotes, dots, spaces, semicolons or upper case (which
 * Postgres would fold, so the name in the config would not be the name in the
 * database). Anything else throws when the store is built.
 */
export function assertPgIdentifier(name: unknown, label: string): string {
  if (typeof name !== 'string' || !PG_IDENTIFIER_RE.test(name)) {
    throw new TypeError(`${label}: must match ^[a-z_][a-z0-9_]{0,62}$ (got ${JSON.stringify(name)})`);
  }
  return name;
}

export function assertExecutor(executor: unknown, label: string): asserts executor is PgExecutor {
  const e = executor as Partial<PgExecutor> | null;
  if (!e || typeof e.query !== 'function' || typeof e.transaction !== 'function') {
    throw new TypeError(`${label}: an executor with query() and transaction() is required`);
  }
}

/**
 * BIGINT and COUNT(*) arrive as strings from both drivers (an int8 can exceed
 * 2^53). Every value stored here is epoch milliseconds or a small counter,
 * well inside the safe range.
 */
export function num(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) throw new TypeError(`expected a number from Postgres, got ${typeof value}`);
  return n;
}

export function numOrNull(value: unknown): number | null {
  return value === null || value === undefined ? null : num(value);
}

/**
 * Rows affected. Throws unless the driver reported a finite number: reading a
 * missing count as 0 would make "nothing happened" out of "unknown". Only used
 * for counts that decide nothing (cleanup totals); decisions use RETURNING.
 */
export function affected(result: PgQueryResult): number {
  const n = (result as { rowCount: unknown }).rowCount;
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    throw new TypeError(`PgExecutor returned rowCount ${String(n)}; it must report affected rows as a number`);
  }
  return n;
}

const RETRYABLE_SQLSTATES = new Set(['40001', '40P01']);

/**
 * Runs `fn`; on a serialization failure (40001) or a deadlock (40P01) runs it
 * exactly once more. Postgres reports both only after rolling the whole
 * transaction back, so nothing of the first attempt took effect and a second
 * one cannot double-count. Every other error is rethrown untouched — above all
 * network errors and timeouts, after which the statement may have committed:
 * running a reservation again there would charge it twice.
 */
export async function retryOnce<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    if (typeof code === 'string' && RETRYABLE_SQLSTATES.has(code)) return fn();
    throw error;
  }
}

/** The executor with every call wrapped in `retryOnce`. */
export function retrying(executor: PgExecutor): PgExecutor {
  return {
    query: (text, params) => retryOnce(() => executor.query(text, params)),
    transaction: (statements) => retryOnce(() => executor.transaction(statements)),
  };
}
