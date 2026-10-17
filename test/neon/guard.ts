/**
 * Safety catch for running the suites against a real Neon database.
 *
 * The suites TRUNCATE every auth_* table and create a schema. Pointed at the
 * wrong database by mistake — an app's own — that would destroy data. So
 * before any of it, the target must contain nothing but auth_* tables: any
 * other table or view in any non-system schema aborts the run, untouched.
 *
 * Erasable TypeScript only (no enums, no namespaces): scripts/test-neon.mjs
 * imports it directly under Node's type stripping.
 */

export const FOREIGN_TABLES_SQL = `
  SELECT table_schema || '.' || table_name AS name
    FROM information_schema.tables
   WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
     AND table_schema NOT LIKE 'pg\\_%'
     AND table_name NOT LIKE 'auth\\_%'
   ORDER BY 1`;

export type GuardQuery = (text: string) => Promise<Array<{ name: unknown }>>;

/** Throws — listing the offending names, never the connection string — unless only auth_* tables exist. */
export async function assertOnlyAuthTables(query: GuardQuery, where: string): Promise<void> {
  const rows = await query(FOREIGN_TABLES_SQL);
  if (rows.length > 0) {
    const names = rows.map((r) => String(r.name)).slice(0, 10).join(', ');
    throw new Error(
      `[neon guard, ${where}] the target database has tables other than auth_* (${names}${rows.length > 10 ? ', …' : ''}). ` +
        'Refusing to run: this does not look like the dedicated test project. Nothing was truncated or created.',
    );
  }
}
