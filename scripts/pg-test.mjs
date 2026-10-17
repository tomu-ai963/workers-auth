#!/usr/bin/env node
/**
 * Starts / stops the throwaway Postgres used by the ./store/pg tests.
 *
 *   node scripts/pg-test.mjs up     generate a password, start, wait until healthy
 *   node scripts/pg-test.mjs down   stop, delete the data and the password file
 *
 * The password is random per `up`, written only to test/pg/.env (gitignored)
 * and never printed. The data lives in tmpfs, so every `up` starts empty.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const envFile = join(root, 'test', 'pg', '.env');
const compose = ['compose', '--env-file', envFile, '-f', join(root, 'test', 'pg', 'docker-compose.yml')];

function docker(args) {
  const r = spawnSync('docker', [...compose, ...args], { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

const command = process.argv[2];
if (command === 'up') {
  const password = randomBytes(24).toString('base64url');
  writeFileSync(envFile, `WA_TEST_PG_PASSWORD=${password}\n`, { mode: 0o600 });
  docker(['up', '-d', '--wait']);
  // initdb hashed the password at the default 4096 SCRAM iterations; store it
  // again under the server's scram_iterations=1 (see docker-compose.yml). The
  // value travels by environment variable and stdin, never on a command line.
  const r = spawnSync(
    'docker',
    ['exec', '-i', '-e', 'P', 'workers_auth_test_db', 'sh', '-c', 'psql -q -v ON_ERROR_STOP=1 -U postgres -d workers_auth_test -v pw="$P"'],
    { input: "ALTER ROLE postgres PASSWORD :'pw';\n", env: { ...process.env, P: password }, stdio: ['pipe', 'ignore', 'inherit'] },
  );
  if (r.status !== 0) process.exit(r.status ?? 1);
  console.log('Postgres ready on 127.0.0.1:55436, Neon HTTP proxy on 127.0.0.1:55446');
} else if (command === 'down') {
  // compose needs the variable defined to parse the file, even to tear down
  if (!existsSync(envFile)) writeFileSync(envFile, 'WA_TEST_PG_PASSWORD=unused\n');
  spawnSync('docker', [...compose, 'down', '-v'], { stdio: 'inherit' });
  rmSync(envFile, { force: true });
} else {
  console.error('usage: node scripts/pg-test.mjs up|down');
  process.exit(2);
}
