#!/usr/bin/env node
/**
 * Starts / stops the throwaway Postgres used by the ./store/pg tests.
 *
 *   node scripts/pg-test.mjs up     generate a password, start, wait until healthy
 *   node scripts/pg-test.mjs down   stop, delete the data and the password file
 *
 * The password is random per `up`, written only to test/pg/.env (gitignored)
 * and never printed. The data lives in tmpfs, so every `up` starts empty.
 *
 * Host ports default to 55436 (Postgres) and 55446 (Neon HTTP proxy). Override
 * them for `up` with WA_TEST_PG_PORT / WA_TEST_PG_HTTP_PORT, e.g. when Windows
 * has reserved the range (`netsh int ipv4 show excludedportrange protocol=tcp`;
 * the reservations move across reboots). `up` writes the chosen ports to
 * test/pg/.env next to the password, so vitest and `down` pick them up from
 * there — the variables are not needed again for `pnpm test`.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const envFile = join(root, 'test', 'pg', '.env');
const compose = ['compose', '--env-file', envFile, '-f', join(root, 'test', 'pg', 'docker-compose.yml')];

const DEFAULT_PORTS = { WA_TEST_PG_PORT: 55436, WA_TEST_PG_HTTP_PORT: 55446 };

function docker(args, env) {
  const r = spawnSync('docker', [...compose, ...args], { stdio: 'inherit', env });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

/** The port from the environment (or its default), or exit with why it is unusable. */
function port(name) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return DEFAULT_PORTS[name];
  const n = /^\d{1,5}$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= 1024 && n <= 65535)) {
    console.error(`${name} must be a port number between 1024 and 65535 (got ${JSON.stringify(raw)})`);
    process.exit(2);
  }
  return n;
}

/** Resolves to null when 127.0.0.1:port can be bound, else the error code. */
function probe(p) {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', (err) => resolve(err.code ?? String(err)));
    server.listen({ host: '127.0.0.1', port: p, exclusive: true }, () => server.close(() => resolve(null)));
  });
}

async function checkFree(name, p) {
  const code = await probe(p);
  if (code === null) return;
  const why =
    code === 'EACCES'
      ? 'is in a range Windows has reserved (netsh int ipv4 show excludedportrange protocol=tcp)'
      : code === 'EADDRINUSE'
        ? 'is already in use (another project, or this one still up: run `pnpm pg:down`)'
        : `cannot be bound (${code})`;
  console.error(`127.0.0.1:${p} ${why}.\nPick a free port with ${name}=<port> pnpm pg:up`);
  process.exit(1);
}

const command = process.argv[2];
if (command === 'up') {
  const pgPort = port('WA_TEST_PG_PORT');
  const httpPort = port('WA_TEST_PG_HTTP_PORT');
  if (pgPort === httpPort) {
    console.error(`WA_TEST_PG_PORT and WA_TEST_PG_HTTP_PORT must differ (both ${pgPort})`);
    process.exit(2);
  }
  await checkFree('WA_TEST_PG_PORT', pgPort);
  await checkFree('WA_TEST_PG_HTTP_PORT', httpPort);

  const password = randomBytes(24).toString('base64url');
  writeFileSync(
    envFile,
    `WA_TEST_PG_PASSWORD=${password}\nWA_TEST_PG_PORT=${pgPort}\nWA_TEST_PG_HTTP_PORT=${httpPort}\n`,
    { mode: 0o600 },
  );
  // Pass the validated ports explicitly: compose lets the shell environment
  // override --env-file, and an empty or stray value there must not win.
  docker(['up', '-d', '--wait'], { ...process.env, WA_TEST_PG_PORT: String(pgPort), WA_TEST_PG_HTTP_PORT: String(httpPort) });
  // initdb hashed the password at the default 4096 SCRAM iterations; store it
  // again under the server's scram_iterations=1 (see docker-compose.yml). The
  // value travels by environment variable and stdin, never on a command line.
  const r = spawnSync(
    'docker',
    ['exec', '-i', '-e', 'P', 'workers_auth_test_db', 'sh', '-c', 'psql -q -v ON_ERROR_STOP=1 -U postgres -d workers_auth_test -v pw="$P"'],
    { input: "ALTER ROLE postgres PASSWORD :'pw';\n", env: { ...process.env, P: password }, stdio: ['pipe', 'ignore', 'inherit'] },
  );
  if (r.status !== 0) process.exit(r.status ?? 1);
  console.log(`Postgres ready on 127.0.0.1:${pgPort}, Neon HTTP proxy on 127.0.0.1:${httpPort}`);
} else if (command === 'down') {
  // compose needs the variable defined to parse the file, even to tear down
  if (!existsSync(envFile)) writeFileSync(envFile, 'WA_TEST_PG_PASSWORD=unused\n');
  spawnSync('docker', [...compose, 'down', '-v'], { stdio: 'inherit' });
  rmSync(envFile, { force: true });
} else {
  console.error('usage: node scripts/pg-test.mjs up|down');
  process.exit(2);
}
