# @tomu-ai/workers-auth

Auth session management for Cloudflare Workers + Hono. Zero runtime dependencies
(Web Crypto only), ESM only, Node 20+.

**The client is deliberately thin and the server holds all state.** No web
storage, no cross-tab broadcast, no background refresh loop. That is a hard
design constraint, not a default — see [Non-goals](#non-goals).

```
Layer 1  SessionStore   persistence        kv / d1 / + revocation list
Layer 2  AuthProvider   identity proof     neon / magic-link / api-key / session-bearer
Layer 3  middleware     Hono integration   auth.middleware(), auth.routes()
Layer 4  client         browser            createAuthClient()
         deviceAuth     PIN + trusted device + email code (own routes, built on layers 1-3)
```

## Install

```bash
npm install @tomu-ai/workers-auth hono
# or: pnpm add @tomu-ai/workers-auth hono
```

Not on the npm registry yet: install from a Git tag
(`npm install github:tomu-ai963/workers-auth#v1.0.0 hono`). `dist/` is not
committed; the `prepare` script builds it during a Git install. Tags before
`v0.3.1` have no `prepare` script and install without `dist/`, so their
imports fail.

Subpaths are split so a project that only wants sessions does not pull in JWKS
verification or D1 code:

| import | contents |
| --- | --- |
| `@tomu-ai/workers-auth` | `createAuth`, middleware, routes, types, crypto/cookie/csrf helpers |
| `@tomu-ai/workers-auth/store/kv` | `kvSessionStore` |
| `@tomu-ai/workers-auth/store/d1` | `d1SessionStore`, `revocationList` |
| `@tomu-ai/workers-auth/store/pg` | `pgSessionStore`, `pgDeviceAuthStore` (Postgres: Neon, or any Postgres via Hyperdrive) — see [Postgres stores](#postgres-stores-storepg) |
| `@tomu-ai/workers-auth/neon` | `neonAuth`, `clearJwksCache` |
| `@tomu-ai/workers-auth/magic-link` | `magicLink`, `kvMagicLinkStore`, `d1MagicLinkStore` |
| `@tomu-ai/workers-auth/api-key` | `apiKey`, `issueApiKey`, `kvApiKeyStore`, `d1ApiKeyStore` |
| `@tomu-ai/workers-auth/session-bearer` | `sessionBearer`, `bearerSessionToken`, `readBearerSession`, `revokeBearerSession` |
| `@tomu-ai/workers-auth/device-auth` | `deviceAuth`, `d1DeviceAuthStore`, `deviceBoundSessionStore`, `isWeakPin`, `pinCredential` — see [PIN + trusted device + email code](#pin--trusted-device--email-code-deviceauth) |
| `@tomu-ai/workers-auth/client` | `createAuthClient` |
| `@tomu-ai/workers-auth/testing` | `readCookieJar`, `cookieHeader`, `loginForCookies`, `waitForEmail`, `extractMagicLinkFromEmail`, `extractEmailCodeFromEmail` — see [Testing your integration](#testing-your-integration) |

## Choosing a session store

Three configurations, three different guarantees. Pick the row that matches
what you actually need — going further than that only adds a D1 dependency for
no benefit.

| configuration | login / logout | revoke one session | log out everywhere |
| --- | --- | --- | --- |
| `kvSessionStore({ allowUnrevocableSessions: true })` | ✅ | ✅ (up to ~60s to propagate) | ❌ — no-op |
| `kvSessionStore({ revocation })` | ✅ | ✅ immediate | ✅ |
| `d1SessionStore()` | ✅ | ✅ immediate | ✅ |
| `d1SessionStore({ revocation })` | ✅ | ✅ immediate | ✅, and cascades to any other store sharing that `revocation` |

KV alone is the simplest and cheapest option, and it is enough for most apps —
"revoke one session" (logout) always works. What it structurally cannot do is
"log out every session of this user": that requires enumerating a user's
sessions, and KV's `list()` is eventually consistent, so a session created just
before the sweep can be missed and survive it silently. Rather than offer that
half-guarantee, `kvSessionStore()` requires you to say which tradeoff you want
**at construction time**: either attach a `revocationList` (one D1 table, no
change to the rest of your stack), or pass `allowUnrevocableSessions: true` to
acknowledge that `revokeAllForUser()` will be a no-op. Neither option is
inferred silently — omitting both throws when you build the store, not when
you eventually call `revokeAllForUser()` during an incident. Switch to
`d1SessionStore()` for anything with a "log out everywhere" / "revoke on
password change" requirement.

The fourth row is not a higher guarantee level than plain `d1SessionStore()`
— D1 alone already gives you all three, immediately, with no extra table.
It's for a narrower situation: **`revocation` is shared with a *different*
`SessionStore` instance** — typically a `kvSessionStore` run alongside this
one, or being migrated away from — so that revoking through *either* store
also invalidates the other's sessions, via the one `RevocationList` both of
them check. If nothing else in your app is reading the same `RevocationList`,
leave `revocation` unset on `d1SessionStore()`: there would be nothing on the
other end to propagate to, and it would only cost writes.

## Minimal setup

Two setups are supported, depending on where your bindings come from. Pick one
— **don't mix `basePath` into the second one**, see why below.

### Per request (bindings only exist inside a request)

```ts
import { Hono } from 'hono';
import { createAuth, getUser, type Auth } from '@tomu-ai/workers-auth';
import { kvSessionStore } from '@tomu-ai/workers-auth/store/kv';
import { neonAuth } from '@tomu-ai/workers-auth/neon';

type Env = { KV: KVNamespace; NEON_JWKS_URL: string };
type Vars = { auth: Auth };

const app = new Hono<{ Bindings: Env; Variables: Vars }>();

app.use('*', async (c, next) => {
  c.set(
    'auth',
    createAuth({
      providers: [
        neonAuth({
          jwksUrl: c.env.NEON_JWKS_URL,
          issuer: 'https://api.stack-auth.com/api/v1/projects/<project-id>',
          audience: '<project-id>',
          cache: { kv: c.env.KV },
        }),
      ],
      store: kvSessionStore(c.env.KV, { allowUnrevocableSessions: true }),
      cookie: { prefix: '__Host-', name: 'session' },
      session: { idleTtlSec: 60 * 60 * 24 * 7, absoluteTtlSec: 60 * 60 * 24 * 30 },
      // Required for the .routes() delegation below — see "basePath" under
      // "What auth.routes() mounts".
      basePath: '/auth',
    }),
  );
  return next();
});

// auth.routes() is a Hono sub-app: a plain (request, env) => Response
// function. Hand it the request directly instead of app.route('/auth', ...),
// which can only mount something built once, up front — not something built
// fresh on every request. basePath: '/auth' above is what lets this sub-app
// match the full incoming path (/auth/session, ...): app.route()'s automatic
// prefix-stripping never runs on this path, since app.route() isn't used
// here. No executionCtx argument is needed either: auth.routes() never
// calls waitUntil itself, and a store given `executionCtx` (see "Deferring
// expired-session cleanup") already holds this request's.
app.all('/auth/*', (c) => c.get('auth').routes().fetch(c.req.raw, c.env));

app.use('/api/*', (c, next) => c.get('auth').middleware()(c, next));
app.get('/api/me', (c) => c.json(getUser(c)));
```

`createAuth` is called per request here because bindings only exist inside a
request in Workers. It allocates nothing expensive: the JWKS cache lives at
module scope and survives across requests inside the isolate.

Because the store is built per request here, it can also take that request's
`executionCtx`, which moves the cleanup of an expired session off the response
path — see [Deferring expired-session cleanup](#deferring-expired-session-cleanup-executionctx).

### Module scope (bindings available outside a request)

```ts
const auth = createAuth({ providers: [...], store: kvSessionStore(env.KV, { allowUnrevocableSessions: true }) });

app.use('/api/*', auth.middleware());
app.route('/auth', auth.routes());
app.get('/api/me', (c) => c.json(getUser(c)));
```

Simpler, and **must not set `basePath`**: `app.route('/auth', auth.routes())`
already strips the matched `/auth` prefix before delegating to the sub-app, so
a sub-app that also expects that prefix baked in would need a request for
`/auth/auth/session` to match anything.

**Don't pass `executionCtx` to a store built here**: there is no request yet,
and a context captured from the first one would be reused by every request
after it. Leave it out; expired sessions are then cleaned up inline, as before
1.1.

### What `auth.routes()` mounts

| method | path | behaviour |
| --- | --- | --- |
| `POST` | `/session` | run `providers` → mint session → set cookies |
| `GET` | `/session` | the current cookie session, or 401 |
| `POST` | `/logout` | revoke session + clear cookies |
| `GET` | `/callback` | run `callbackProviders` → mint session → 302 (only mounted when `callbackProviders` is non-empty) |

`POST /session` and `POST /logout` require an `Origin` header. Browsers always
send one; a server-side caller must set it explicitly.

Every response from these routes carries `Cache-Control: no-store, private` and
`Vary: Cookie, Authorization` unconditionally — an identity response is never
safe to cache, and this is enforced on the server so a CDN rule, service worker
or proxy in front of the Worker cannot serve one user's session to another.

`GET /session` only reads the cookie session; it does not run `providers`. A
`GET` must not have side effects, and provider verification can (a magic-link
token is single-use) — so it never runs on a route that isn't supposed to
authenticate anyone with it.

#### `basePath`

`createAuth({ basePath })` bakes a path prefix into `auth.routes()` itself
(via Hono's own `basePath()`), so the returned sub-app matches
`${basePath}/session` etc. against the *full* request path it's given.

This only matters for one specific mounting style: handing `auth.routes()`
a request directly (`auth.routes().fetch(request, env)`), which is what the
per-request setup above does because `createAuth()` has to be rebuilt on every
request and therefore can't be mounted once, up front, with `app.route()`.
Without `basePath`, that sub-app only knows about its own bare paths
(`/session`, not `/auth/session`), so every request to it 404s.

If you mount the ordinary way — `app.route('/auth', auth.routes())`, built
once at module scope — leave `basePath` unset. `app.route()` already strips
the matched prefix before delegating, so setting `basePath` too would apply
the prefix twice.

### Reading the subject

```ts
app.use('/api/*', auth.middleware());
app.get('/api/me', (c) => c.json(getUser(c)));           // throws if unauthenticated

app.use('/public/*', auth.middleware({ optional: true }));
app.get('/public/hello', (c) => {
  const user = getOptionalUser(c);                        // AuthUser | undefined
  return c.json({ hello: user?.id ?? 'anonymous' });
});
```

`c.get('user')` is typed through Hono's `ContextVariableMap`. The cookie
session's metadata is on `c.get('authSession')` (or `getSession(c)`) — its raw
credential is not: the type is `SessionInfo`, `Session` minus `sid`, so the
value that would matter if it leaked is simply not reachable from application
code.

## Layer 1: session stores

### `kvSessionStore(namespace, options?)` — default

Two keys per session: `sess:<sha256(sid)>` holds the immutable part (identity,
absolute expiry), written once at `create()`. `seen:<sha256(sid)>` holds the
sliding idle window, written by `touch()`. They are split on purpose — KV has
no compare-and-set, so if `touch()` rewrote the session record, a write already
in flight could land *after* a concurrent `revoke()` and bring a logged-out
session back to life. With the split, a late `touch()` write only creates a
stray marker for a record that is already gone, which `get()` ignores.

Both expiries are also checked in code on every read — KV's 60s minimum TTL and
eventually-consistent deletes make the TTL garbage collection, not access
control. `touch()` throttles its own writes (`touchThrottleSec`, default 10) to
stay under KV's per-key write-rate limit on an active session.

Construction itself requires you to pick a revocation posture: either pass
`revocation: revocationList(env.DB)`, or pass `allowUnrevocableSessions: true`
to acknowledge that `revokeAllForUser()` will be a no-op. Omitting both throws
immediately, rather than deferring the failure to the moment
`revokeAllForUser()` is actually called — typically during incident response,
the worst time to discover a missing dependency for the first time. Whichever
you picked is readable back off the store as `store.canRevokeAllForUser`
(`true` with a revocation list, `false` with `allowUnrevocableSessions`), so
code that cares — an audit log, an admin UI — can check it instead of
inferring the answer from `revokeAllForUser()` doing nothing. See
[Choosing a session store](#choosing-a-session-store).

### `d1SessionStore(db, options?)`

Strongly consistent, so revocation — including `revokeAllForUser()` — is
immediate and needs no extra table. Costs one D1 read per authenticated
request. Exposes an extra `cleanup(now?)` for a cron trigger. Apply
`migrations/0001_sessions.sql` first.

Also accepts `revocation`, but only for the case where it's the *same*
`RevocationList` another `SessionStore` (typically a `kvSessionStore`) is
also using — see the fourth row under
[Choosing a session store](#choosing-a-session-store). Leave it unset
otherwise; this store doesn't need it for anything of its own.

### `revocationList(d1, options?)` — KV + full revocation guarantees

```ts
import { kvSessionStore } from '@tomu-ai/workers-auth/store/kv';
import { revocationList } from '@tomu-ai/workers-auth/store/d1';

const store = kvSessionStore(env.KV, { revocation: revocationList(env.DB) });
```

One D1 round trip on `get()` answers two questions at once:

- **is this session revoked** — `revoke(sid)` writes `sha256(sid)` to
  `auth_revocations` as a tombstone (`migrations/0002_revocations.sql`);
- **were all of this user's sessions revoked** — `revokeAllForUser(userId)`
  writes a single `revoked_before` timestamp to `auth_user_revocations`
  (`migrations/0005_user_revocations.sql`); a session is invalid if it was
  created before that timestamp. This needs no session enumeration, so it
  cannot miss a session the way a `list()`-based sweep can.

`revocationList(...).cleanup()` deletes rows that can no longer affect any live
session. **The per-user marker has no expiry of its own** — deleting it early
would silently un-revoke every session created before it — so cleanup keeps it
around for `maxSessionLifetimeSec` (default 90 days; set it to the longest
`absoluteTtlSec` you configure anywhere).

### Deferring expired-session cleanup (`executionCtx`)

When `get()` finds a session past its idle or absolute expiry, it returns
`null` and deletes it: two `kv.delete()` calls for `kvSessionStore`, one
`DELETE` for `d1SessionStore` and `pgSessionStore`. By default that delete is
awaited, so the one request that happens to find the expired session pays for
it. Give the store the request's `ExecutionContext` and the delete goes to
`ctx.waitUntil()` instead:

```ts
store: kvSessionStore(c.env.KV, {
  allowUnrevocableSessions: true,
  executionCtx: executionCtxOf(c),
}),
// the same option on d1SessionStore(c.env.DB, { executionCtx: ... })
// and pgSessionStore(executor, { executionCtx: ... })
```

- **The delete is issued at once; only the wait moves.** `get()` sends it
  before returning and hands the pending promise to `waitUntil` — it is not
  queued to start after the response.
- **The answer does not change.** `get()` returns `null` in that request, and
  a second request for the same `sid` that arrives before the delete lands
  gets `null` too: expiry is read from the stored record, not from whether the
  key or row is still there.
- **A failed deferred delete is dropped silently.** Access was already decided,
  and the leftover is expired data: KV's `expirationTtl` or the store's
  `cleanup()` removes it later. It is not rethrown (nothing is left to receive
  it) and not an unhandled rejection. Without `executionCtx` a failed delete
  still rejects `get()`, as before.
- **Only for a store built inside the request** — the per-request setup. See
  [Module scope](#module-scope-bindings-available-outside-a-request) for why
  not the other one. If `waitUntil` itself throws, `get()` falls back to
  awaiting the delete.
- **The option takes anything with `waitUntil(promise)`**
  (`WaitUntilContext`): Hono's `c.executionCtx` as-is, or a plain object in
  tests.

Hono's `c.executionCtx` is a getter that **throws** when the request has no
`ExecutionContext` — `app.request()` in tests, for one. Read it like this, so
those requests just keep the awaited behaviour:

```ts
import type { Context } from 'hono';
import type { WaitUntilContext } from '@tomu-ai/workers-auth';

/** The request's ExecutionContext, or undefined where Hono has none (app.request() in tests). */
export function executionCtxOf(c: Context): WaitUntilContext | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}
```

With Postgres, see the note on closing the connection under
[Postgres stores](#postgres-stores-storepg).

### Postgres stores (`./store/pg`)

For apps whose data already lives in Postgres (Neon), so auth does not need a
D1 database of its own. `pgSessionStore(executor, options?)` and
`pgDeviceAuthStore(executor, options?)` are drop-in counterparts of
`d1SessionStore` and `d1DeviceAuthStore`: same interface, same limits, the
same test suites (every `deviceAuth` test runs against both). There is no
Postgres version of the magic-link, API-key or revocation-list stores.

The package ships **no Postgres driver** and declares none, not even as a peer.
You pass an *executor* — two functions — built from the driver you already use:

```ts
type PgExecutor = {
  // One statement, autocommit. rowCount: affected/returned rows, as a number.
  query(text: string, params: readonly unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;
  // Runs the statements in order in ONE transaction; all or nothing.
  transaction(statements: readonly { text: string; params: readonly unknown[] }[]): Promise<{ rows; rowCount }[]>;
};
```

**`rowCount` must be a number (required).** Drivers can report `null` (`pg`
does for commands without a count). Throw in the adapter rather than passing
`null` on or turning it into `0`: "unknown" read as "no rows" is how a PIN
change could quietly skip signing the other devices out. The stores decide
everything that matters from `RETURNING` rows, and throw if a count they do
read (cleanup totals) is not a finite number — the adapters below do the same.

**Neon over HTTP (`@neondatabase/serverless`) — the default.** One HTTPS round
trip per query, no connection to open or close, nothing to set up per request:

```ts
import { neon } from '@neondatabase/serverless';
import type { PgExecutor } from '@tomu-ai/workers-auth/store/pg';

function counted(r: { rows: Record<string, unknown>[]; rowCount: number | null }) {
  if (typeof r.rowCount !== 'number') throw new Error('neon: no row count in the result');
  return { rows: r.rows, rowCount: r.rowCount };
}

export function neonExecutor(databaseUrl: string): PgExecutor {
  const sql = neon(databaseUrl, { fullResults: true });
  return {
    query: async (text, params) => counted(await sql.query(text, [...params])),
    transaction: async (statements) =>
      (
        await sql.transaction(statements.map((s) => sql.query(s.text, [...s.params])), { isolationLevel: 'ReadCommitted' })
      ).map(counted),
  };
}

const executor = neonExecutor(env.DATABASE_URL); // a `wrangler secret`, the primary's connection string
const devices = pgDeviceAuthStore(executor);
const sessions = deviceBoundSessionStore(pgSessionStore(executor), devices);
```

**`pg` behind Hyperdrive.** Needs `nodejs_compat`; create the client per
request and close it when the response is done:

```ts
import { Client, type QueryResult } from 'pg';

function counted(r: QueryResult) {
  if (r.rowCount === null) throw new Error(`pg: no row count for ${r.command}`);
  return { rows: r.rows, rowCount: r.rowCount };
}

export function clientExecutor(client: Client): PgExecutor {
  return {
    query: async (text, params) => counted(await client.query(text, [...params])),
    async transaction(statements) {
      await client.query('BEGIN');
      try {
        const results = [];
        for (const s of statements) results.push(counted(await client.query(s.text, [...s.params])));
        await client.query('COMMIT');
        return results;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      }
    },
  };
}

const client = new Client({ connectionString: env.HYPERDRIVE_AUTH.connectionString });
await client.connect();
ctx.waitUntil(/* after the response */ client.end());
```

With `pgSessionStore(executor, { executionCtx: ctx })` on this client, an
expired session's `DELETE` is sent from inside `get()`, during the request —
not started later from `waitUntil` — so it has the rest of the request to
finish before `client.end()` above runs. That makes the race with the close
unlikely, not impossible: `pg` (8.x, not pipelined) **destroys the socket** if
`end()` is called while a query is still running, and a driver whose `end()`
takes a timeout (postgres.js `sql.end({ timeout: 5 })`) cuts it off once that
expires. A `DELETE` lost that way is swallowed like any other deferred delete,
and the row stays until `cleanup()` — the session was already answered `null`
and stays `null`. Neon over HTTP has no connection to close, so none of this
applies there.

Both adapters are the ones the test suite uses (the Neon one against a local
Neon HTTP proxy, the `pg` one for the row-lock tests).

What the stores rely on — each one is load-bearing for revocation or a limit:

- **Autocommit only — never inside a transaction your app opened.** Every
  limit reserves its failure *before* checking a PIN or code, in a statement
  that commits on its own. Run the executor inside an app transaction and a
  rollback (an error later in the request, or the app's own) undoes those
  reservations: the guesses come back, and the PIN and email-code limits stop
  limiting. `query()` must be one autocommitted statement; `transaction()`
  must open and commit its own transaction. There is no reliable way for the
  store to detect the misuse itself (see SECURITY.md), so it is on the adapter.
- **One connection per request; do not share a `pg` Client across
  requests.** A shared client mixes requests' statements on one session —
  including into whatever transaction another request has open — which is the
  previous point by accident. (Neon HTTP has no connection to share.)

- **Hyperdrive must be created with `--caching-disabled`.** Hyperdrive caches
  read queries for 60 s by default and does not invalidate them on writes, so
  a cached `SELECT` would keep a revoked session, a revoked device or an old
  rate-limit count alive. Use a separate cache-disabled configuration for auth
  if the rest of the app wants caching:
  `npx wrangler hyperdrive create auth-fresh --connection-string=... --caching-disabled`.
- **No read replicas.** Point the executor at the primary (read-write)
  endpoint. A replica's lag is the same stale read.
- **READ COMMITTED** — Postgres' default. Every limit is one conditional
  statement (`INSERT … ON CONFLICT DO UPDATE … WHERE … RETURNING`, or
  `UPDATE … WHERE … RETURNING`), and READ COMMITTED is what makes such a
  statement wait for a concurrent writer and then re-check its condition
  against the row that writer left. A database whose default is REPEATABLE
  READ or SERIALIZABLE turns that wait into an error (40001); the stores retry
  a 40001 or 40P01 (deadlock) once — and nothing else, because after a network
  error or timeout the statement may already have committed.
- **Two spots that D1 got for free from its single writer** are handled
  explicitly: replacing a PIN takes a transaction-scoped advisory lock on the
  account (key: `hashtextextended('workers-auth:credential:' || account_id, 0)`;
  without it two concurrent PIN changes end in a unique violation), and
  clearing the lockout state is one statement that locks the row first.
- **No retrying `fetch` under Neon HTTP.** Do not set
  `neonConfig.fetchFunction` to a `fetch` that retries on its own. The stores
  deliberately do not retry after a network error or timeout — the statement
  may already have committed, and running a failure reservation twice would
  charge it twice. The driver itself sends each query once (checked in
  `@neondatabase/serverless` 1.2.0: one `fetch`, no retry loop); a retrying
  `fetchFunction` would quietly reintroduce exactly that double run.

`schema` (default `public`) selects where the tables live. It must match
`^[a-z_][a-z0-9_]{0,62}$` and is checked when the store is built. Neon Auth's
`neon_auth` schema is untouched either way; every table here is `auth_*`.

**Cold starts.** A Neon compute that has scaled to zero adds its start-up to
the first query that reaches it: about **0.7 s** on top of a normal first
query, measured against a 0.25 CU test project in aws-ap-southeast-1 (first
query after idle 1.18 s, first query from a fresh process on a running
compute 0.45 s, warm queries ~0.1 s — from a development machine, not from a
Worker). Authentication runs on every request, so the user who wakes the
compute feels it; configure autosuspend accordingly for production.

**A least-privilege role for auth.** The stores need no DDL, no `TRUNCATE`
and no access to anything but their own tables. After the migrations, as the
database owner (create the role itself in the Neon console or API):

```sql
GRANT USAGE ON SCHEMA public TO workers_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  auth_sessions, auth_email_codes, auth_trusted_devices, auth_credentials, auth_rate_limits
  TO workers_auth_app;
GRANT SELECT, INSERT, UPDATE ON auth_login_guards TO workers_auth_app;  -- never deleted from
```

With a `schema` other than `public`, grant on that schema and its tables
instead. The advisory-lock and hashing functions the stores call are
executable by every role by default. These grants are verified on a local
PostgreSQL 17 by `test/pg-node/least-privilege.test.ts`: a role holding
exactly them runs every store method, and `TRUNCATE`, DDL and other tables
are refused (42501).

## Layer 2: providers

Providers are tried in array order and the first success wins. Provider-specific
values live in `AuthUser.claims`, never on the top level — that is what keeps
providers swappable. The one exception is `AuthUser.rateLimitId`: every
provider sets it to whatever it treats as the stable identifier to rate-limit
on (`apiKey` → the key id, `neonAuth` → the JWT `sub`, `magicLink` → the
verified email, or whatever a `resolveUser` callback returns), so a rate
limiter can always read `user.rateLimitId` without knowing which provider is
configured. See [SECURITY.md](./SECURITY.md#authuserratelimitid) for why this
one field is top-level and how each provider picks its value.

### `neonAuth({ jwksUrl, issuer, audience })`

JWKS verification for RS256 / ES256 / EdDSA (RS384, RS512 and ES384 are also
available via `algorithms`). `iss`, `aud`, `exp` and `nbf` are all enforced,
with a 30 second default clock-skew tolerance (`clockToleranceSec`) — enough to
absorb ordinary drift between the issuer and the edge without turning it into
sporadic 401s, without extending an expired token's effective lifetime too far.
See [SECURITY.md](./SECURITY.md#jwt-verification-neonauth) for the tradeoff.

The JWKS is cached at module scope and optionally in KV (`cache: { kv }`). An
unknown `kid` triggers exactly one refetch, rate limited to one network call
per `minRefetchIntervalSec` (default 60), so key rotation is picked up without
turning the endpoint into an amplifier. The fetch itself is bounded:
`fetchTimeoutMs` (default 3000), `maxJwksBytes` (default 256KB) and
`maxJwksKeys` (default 32) — a hung or hostile JWKS endpoint fails a single
request instead of stalling every authenticated request behind it.

### `magicLink({ store, sendToken, ttlSec })`

**This SDK does not send email.** Inject the sender:

```ts
import { magicLink, d1MagicLinkStore } from '@tomu-ai/workers-auth/magic-link';

const provider = magicLink({
  store: d1MagicLinkStore(env.DB),
  ttlSec: 900,
  allowTokenInQuery: true,   // required to read ?token= — see below
  sendToken: async (email, token) => {
    await sendWithYourProvider(email, `https://app.example.com/auth/callback?token=${token}`);
  },
  resolveUser: async (email) => lookupUser(email),   // optional; default id = email
  // ^ lookupUser's returned AuthUser must set its own rateLimitId — this
  // provider can't guess a stable key for a record it didn't create.
});

const auth = createAuth({
  providers: [],                    // NOT here
  callbackProviders: [provider],    // only /callback runs this
  store: kvSessionStore(env.KV, { allowUnrevocableSessions: true }),
});

await provider.start('user@example.com');   // always returns { ok: true }
```

Two properties, both non-negotiable:

- **Single use.** Tokens are 256-bit, stored as SHA-256, and consumed with an
  atomic take. `d1MagicLinkStore` does this with `DELETE ... RETURNING` — one
  statement, so exactly one of two racing requests can get the row. That
  atomicity, not D1's consistency model, is what makes the guarantee hold.
  `kvMagicLinkStore` cannot offer it (KV has no atomic read-and-delete: `take()`
  is a `get` then a `delete`, so two concurrent requests can both see the same
  token — this reproduces even against a strongly consistent store, because it
  is a plain interleaving, not an eventual-consistency artefact). `magicLink()`
  refuses a non-atomic store at construction; the escape hatch is named
  `dangerouslyAllowReplayableTokens: true` and there is no good reason to use it
  outside a prototype.
- **Confined to the callback route.** A token in the URL leaks through Referer
  headers, browser history, access logs and shared inboxes. If any provider
  read `?token=` on every route, one of those leaks would let an attacker both
  authenticate *and* burn the real link on an unrelated endpoint. So reading the
  query string is opt-in (`allowTokenInQuery: true`), and a provider configured
  that way must go in `callbackProviders`, not `providers` — `createAuth()`
  throws if it ends up in the wrong array. Without `allowTokenInQuery`, the
  token can still be sent via the `x-magic-token` header or a JSON body — useful
  for an SPA landing page that reads the query string itself and POSTs the token
  to `/session`.

`start()` does identical work for every address and swallows delivery errors
into `onSendError`, so it cannot be used to enumerate accounts. Rate limiting
`start()` is your job.

`d1MagicLinkStore(...).cleanup(now?)` deletes expired, never-consumed tokens —
run it from a cron trigger. A consumed token is already removed by `take()`, so
only abandoned ones ever need sweeping.

### `apiKey({ store })` — service to service

```ts
import { apiKey, issueApiKey, d1ApiKeyStore } from '@tomu-ai/workers-auth/api-key';

const store = d1ApiKeyStore(env.DB);
const { key } = await issueApiKey({ store, env: 'live', subjectId: 'svc_reporting' });
// key === 'tk_live_<keyId>.<secret>' — show it once, it is not recoverable

const provider = apiKey({ store, env: 'live' });     // -> subjectType: 'service'
```

Only `sha256(secret)` is stored, and comparison is timing-safe — including for
unknown key ids, which take the same path.

## PIN + trusted device + email code (`deviceAuth`)

Magic links are safe but tedious: every login is a trip to the inbox. This
module replaces that with:

1. **New device** — enter an email address, type the 6-digit code that arrives,
   and the device becomes *trusted*. If the account has no PIN yet, set one.
2. **Trusted device** — the PIN alone.
3. **3 wrong PINs in a row** — the account's PIN login stops until an email
   code succeeds again.

It is not an `AuthProvider` (a PIN login has a failure counter as a side
effect, and its "verify your email" answer cannot be expressed as `null`). It
mounts its own routes and mints sessions through the `Auth` you give it, so the
session store, cookie config and `onEvent` are shared with everything else
(there is no separate `onEvent` option — events go to `createAuth`'s). The
existing `magicLink` provider is untouched and can run alongside it; a
magic-link login does **not** lift a PIN lockout — only an email code does.

```
new device:     POST /email/start {email}       -> 200 {ok}   (same answer for every address)
                POST /email/verify {email,code} -> session + trusted device, {pinSet}
                POST /pin {pin}                 (needs an email verification < 10 min old)
trusted device: POST /pin/login {pin}           -> session
                  no / revoked / expired device -> 401 email_verification_required  (no PBKDF2 run)
                  account locked                -> 401 email_verification_required  (no PBKDF2 run)
                  wrong PIN                     -> 401 {invalid_pin, attemptsRemaining}
                  3rd wrong PIN                 -> 401 email_verification_required  (account locked)
```

Apply `migrations/0006_device_auth.sql` (D1) or `migrations/pg/0006_device_auth.sql`
(Postgres). The store is `d1DeviceAuthStore` or `pgDeviceAuthStore`
([Postgres stores](#postgres-stores-storepg)) — there is no KV version:
`deviceAuth()` refuses a store that does not declare `atomic: true`, because
every limit here (5 tries per code, 10 failures per address or per trusted
device per day window, 3 PIN failures, resend cooldowns) must hold under
concurrent requests and KV cannot do that.

### Three things `deviceAuth()` checks at construction

It throws, rather than letting a gap surface during an incident, unless:

1. **The session store is wrapped with `deviceBoundSessionStore(store,
   deviceStore)`.** Every session minted on a trusted device records that
   device; the wrapper checks the device on every `get()` (one D1 point read,
   only for such sessions) and refuses — and deletes — the session once the
   device is revoked, expired, or no longer the account's. That is what makes
   revoking a device end the sessions on it, for cookie and bearer sessions
   alike. Use the same database for both stores.

   Only the exact object `deviceBoundSessionStore()` returns counts — it is
   recorded in a registry, so an `Object.create()` of it or an app wrapper
   around it is *not* device-bound, and `deviceAuth()` refuses it. The cookie
   middleware and `sessionBearer()` also refuse any session minted on a
   trusted device that they read through a store other than that object (a
   second `createAuth()` over the same table, say). If you wrap the store
   yourself (logging, metrics), put your wrapper **inside**:
   `deviceBoundSessionStore(myWrapper(d1SessionStore(env.DB)), devices)`.

   **If you write your own provider (or any code) that reads sessions
   directly, read them through the store `deviceBoundSessionStore()`
   returned** — the same one given to `createAuth`. Calling `get()` on the raw
   inner store skips the device check: a session minted on a revoked or
   expired device comes back as if it were live. The SDK's own readers
   (`auth.middleware()`, `readCookieSession`, `readBearerSession`,
   `sessionBearer()`) refuse such sessions from an unwrapped store; code that
   calls `store.get()` itself has no such guard.
2. **The session store can `revokeAllForUser()`** (`canRevokeAllForUser`):
   `d1SessionStore`, or `kvSessionStore` with a `revocationList`.
   "Revoke all devices" and `revokeOtherDevicesOnChange` end every session of
   the account with it.
3. **Every `sessionBearer()` provider reads that same wrapped store.**

### Choosing a transport

`transport` is required — there is no default, because the right answer
depends on where the frontend lives.

| | `'cookie'` | `'response'` |
| --- | --- | --- |
| layout | frontend and API on the **same site** | frontend and API on **different sites** (`*.github.io` and `*.workers.dev`) |
| device token | `__Host-device` cookie, HttpOnly / Secure / SameSite=Lax | `deviceToken` in the JSON body; send back as `x-device-token` |
| session | the usual cookie session | `sessionToken` (`wsb_…`) in the body; send as `Authorization: Bearer` |
| CSRF | Origin check on every POST (+ double-submit once a CSRF cookie exists) | not applicable — nothing is ambient |

Why `'response'` exists at all: across sites, the session cookie is a
third-party cookie and Safari (among others) drops it, so a cookie-only setup
silently fails after login. In `'response'` mode the **app** decides where to
keep the two tokens (this SDK's own client still keeps nothing — see
[Non-goals](#non-goals)). A bearer session is readable by page JS, so it is
short-lived: **12 hours, no sliding** by default (`bearerSessionTtlSec`). The
device token lives up to a year, so getting a new session on a trusted device
costs only the PIN. The two kinds never cross over: a bearer session id sent
as the session cookie is refused, and a cookie session id sent as a bearer
token is refused.

### Same-site setup (`transport: 'cookie'`)

```ts
import { Hono } from 'hono';
import { createAuth, getUser } from '@tomu-ai/workers-auth';
import { d1SessionStore } from '@tomu-ai/workers-auth/store/d1';
import { d1DeviceAuthStore, deviceAuth, deviceBoundSessionStore } from '@tomu-ai/workers-auth/device-auth';

type Env = { DB: D1Database; DEVICE_AUTH_SECRET: string; DEVICE_AUTH_PREVIOUS_SECRETS?: string };

const app = new Hono<{ Bindings: Env }>();

function build(env: Env) {
  const devices = d1DeviceAuthStore(env.DB);
  const sessions = deviceBoundSessionStore(d1SessionStore(env.DB), devices);
  const auth = createAuth({ providers: [], store: sessions });
  const device = deviceAuth({
    auth,
    store: devices,
    transport: 'cookie',
    secret: env.DEVICE_AUTH_SECRET,
    previousSecrets: env.DEVICE_AUTH_PREVIOUS_SECRETS?.split(',').filter(Boolean),
    sendCode: (email, code) => sendWithYourProvider(email, `Your code: ${code}`),
    resolveUser: (email) => findOrCreateUser(env.DB, email), // -> AuthUser | null
  });
  return { auth, device };
}

// Built per request because bindings only exist inside one. The sub-app is
// mounted under the same prefix so it sees the full path.
app.all('/auth/device/*', (c) =>
  new Hono().route('/auth/device', build(c.env).device.routes()).fetch(c.req.raw, c.env),
);
app.use('/api/*', (c, next) => build(c.env).auth.middleware()(c, next));
app.get('/api/me', (c) => c.json(getUser(c)));
```

The page calls these with `credentials: 'include'` and echoes the `__Host-csrf`
cookie as `x-csrf-token` (what `createAuthClient` already does for `/session`).

### Cross-site setup (`transport: 'response'`)

```ts
import { cors } from 'hono/cors';
import { sessionBearer } from '@tomu-ai/workers-auth/session-bearer';

function build(env: Env) {
  const devices = d1DeviceAuthStore(env.DB);
  const sessions = deviceBoundSessionStore(d1SessionStore(env.DB), devices);
  // sessionBearer() is what lets auth.middleware() accept `Authorization: Bearer wsb_…`.
  const auth = createAuth({ providers: [sessionBearer({ store: sessions })], store: sessions });
  const device = deviceAuth({ auth, store: devices, transport: 'response', /* ...as above */ });
  return { auth, device };
}

// A fixed origin, no credentials: nothing here relies on cookies.
app.use('*', cors({
  origin: 'https://you.github.io',
  allowHeaders: ['content-type', 'authorization', 'x-device-token'],
  allowMethods: ['GET', 'POST'],
}));
```

```ts
// frontend (sketch)
const r = await fetch(`${API}/auth/device/email/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email, code }),
}).then((res) => res.json());
// r.deviceToken (only when a new device was registered), r.sessionToken, r.pinSet
```

### Routes

All mounted under wherever you `route()` them (`/auth/device` above). Every
response is `Cache-Control: no-store`. Request bodies are JSON, at most
**4 KB** (`413 payload_too_large` otherwise).

| route | needs | does |
| --- | --- | --- |
| `POST /email/start` `{email}` | — | sends a code; `200 {ok:true}` for every address, or `429 {rate_limited, retryAfterSec}` |
| `POST /email/verify` `{email, code, trustDevice?, deviceLabel?}` | — | session + trusted device (`trustDevice` defaults to `true`), clears a PIN lockout; `{ok, user, pinSet, device, deviceToken?, sessionToken?}`. A repeat email login on an already-trusted device of the same account reuses (and extends) that device instead of registering a new one |
| `POST /pin` `{pin}` | session from an email code < `freshEmailAuthSec` old | sets / changes / resets the PIN (one path for all three). With `revokeOtherDevicesOnChange` and an existing PIN: `{ok, signedOut: true}` — see below |
| `GET /pin/status` | session | `{pinSet}` |
| `POST /pin/login` `{pin}` | device token | session |
| `GET /devices` | session | `{devices, currentDeviceId}` |
| `POST /devices/:deviceId/revoke` | session | revokes one of *your* devices; the sessions minted on it stop working on their next request |
| `POST /devices/revoke-all` | session | revokes all of your devices **and every session of the account, this one included** |
| `POST /device/forget` | device token | revokes this device (and so its sessions), clears its cookie |
| `POST /logout` | session | ends the current session (cookie or bearer); the device stays trusted |

Error bodies: `invalid_request` (400), `invalid_pin_format` / `weak_pin` (400),
`client_ip_required` (400, only with `requireClientIp`), `invalid_code` (401),
`invalid_pin` + `attemptsRemaining` (401), `email_verification_required` (401),
`unauthenticated` (401), `csrf_failed` / `bot_check_failed` (403),
`payload_too_large` (413), `rate_limited` + `retryAfterSec` (429),
`temporarily_unavailable` (503, only with `circuitBreaker`).

Also on the returned object: `requireFreshEmailAuth(maxAgeSec?)` (middleware
for your own sensitive routes), `listDevices`, `revokeDevice` (ends that
device's sessions), `revokeAllDevices` (ends every session of the account),
`hasPin`. The subpath also exports `generateEmailCode` (used by the tests),
`ipRateLimitKey`, `isWeakPin` and `estimateEntropyBits`.

`deviceLabel` (≤ 100 characters) is stored and returned exactly as the client
sent it. **Escape it when you render it** — it is user input, and an
unescaped label in a "your devices" page is a stored XSS.

### Options worth knowing

| option | default | |
| --- | --- | --- |
| `device.idleTtlSec` | 90 days | extended by every PIN login (and a repeat email login on that device) |
| `device.absoluteTtlSec` | 365 days | from registration; never extended |
| `pin.iterations` | 100,000 | PBKDF2-SHA256; 1,000–100,000 (Workers' cap) |
| `pin.maxAttempts` | 3 | consecutive failures before lockout, per account |
| `pin.isWeakPin` | — | extra rule, on top of the built-in one |
| `pin.rejectDateLike` | `false` | also refuse DDMMYY / MMDDYY / YYMMDD / YYYYMM / MMYYYY |
| `pin.revokeOtherDevicesOnChange` | `false` | on replacing an existing PIN: revoke the other devices **and every session of the account**, including the caller's (`signedOut: true`; the current device stays trusted, so it logs in again with the new PIN). The new PIN and the devices' revocation are one transaction: both happen or neither |
| `emailCode.ttlSec` / `.maxAttempts` | 600 / 5 | a resend inside the first code's lifetime keeps the attempts already used |
| `emailCode.digits` | 6 | 6 or 8 |
| `emailCode.maxFailuresPerEmail` / `.failureWindowSec` | 10 / 86,400 | failures per address across all its codes, per fixed window — see the trade-off below |
| `emailCode.maxFailuresPerDevice` | 10 | the separate budget for requests that present a trusted device of the address — see below |
| `normalizeEmail` | trim + lower-case | the address everything is keyed on |
| `freshEmailAuthSec` | 600 | how recent an email code `POST /pin` needs |
| `bearerSessionTtlSec` | 43,200 (12 h) | `'response'` only |
| `limits.resendCooldownSec` | 60 | per address (per device, for a request presenting one of the address's devices) |
| `limits.codesPerEmailPerHour` | 5 | same split as the cooldown |
| `limits.startsPerIpPerHour` / `verifiesPerIpPerHour` / `pinLoginsPerIpPerHour` | 20 / 60 / 60 | per IPv4 address, per IPv6 **/64** |
| `getClientIp` | `CF-Connecting-IP` | see below |
| `requireClientIp` | `false` | `true` refuses requests with no client IP instead of skipping per-IP limits |
| `botCheck` | — | `(req, 'email_start' \| 'email_verify' \| 'pin_login') => boolean`; false or a throw → `403 bot_check_failed` |
| `circuitBreaker` | off | `{ minFailures, maxFailureRatio = 0.5, windowSec = 600 }` — see below |

**The per-address failure cap, and its trade-off.** Each address gets 10
failed verifications (across however many codes) per fixed 24-hour window.
The window is fixed, not sliding: 10 per window, so up to 20 within 24 hours
when they straddle a window boundary. Only a check against a live code
counts — successful verifications, and verifies with no code to try (none
sent, expired, or its 5 attempts already used), cost nothing. A slot is taken
only while the budget has one free, in the same statement that checks it, so
a verify refused at the cap adds nothing either — however many arrive at
once. To spend the budget an attacker therefore has to request codes (each
one is emailed to the owner) and make wrong guesses against them: 10 wrong
guesses on live codes, which takes at least two codes, since one code allows
5 attempts and a resend within its 10 minutes keeps the attempts already
used.

Once the budget is spent, `/email/start` and `/email/verify` answer `429` for
that address until the window ends — to every request that does not present
a trusted device of the address. Anyone who knows the address can do this.
What it stops, for that long, for anyone not on a live trusted device of the
address:

- logging in on a new device (or any device not trusted for this address);
- unlocking a PIN locked by 3 wrong attempts;
- setting or changing the PIN (`POST /pin` needs a fresh email verification);
- your own routes behind `requireFreshEmailAuth()`;
- logging in at all for a user with no PIN, or whose trusted device has
  expired or been revoked (email is their only way in).

**PIN login on a trusted device is not affected.** And **a user who holds a
trusted device of the address can still recover**: a request that presents a
valid (unrevoked, unexpired) device registered to that address is counted
against that device's own budget — `emailCode.maxFailuresPerDevice` failures
per window, plus its own resend cooldown and hourly send cap — and never
against the address's. Someone without the device cannot spend that budget.
Someone who took the device gets that budget *and* the address's, since they
can always leave the device out: per window, `maxFailuresPerDevice` plus
`maxFailuresPerEmail` guesses (10 + 10 = 20 by default), and 10 × (N + 1) with
N stolen devices of the address. So the owner
of a locked PIN asks for a code *from their trusted device*, verifies it
there, and the PIN is unlocked. A user with no live trusted device has to wait
out the window. That is the price of capping how many guesses an attacker gets
against one address: without it, resending kept refilling the budget.

**Normalising addresses.** Everything is keyed on `normalizeEmail(input)`.
If your accounts treat `a.b+tag@gmail.com` and `ab@gmail.com` as one user, do
that canonicalisation in `normalizeEmail`, not only inside `resolveUser` —
otherwise each spelling gets its own limits against the same account.

**`sendCode` and `onSendError`.** `sendCode` is called for every
valid-looking address; do not branch on whether an account exists (the
response waits for the send, so a skipped send is visible as a faster
response). `onSendError` receives whatever your provider threw, which may
include the request it failed on — recipient, subject, even the body with the
code. Log a status or error name, not the object.

**`getClientIp`.** On Cloudflare, `CF-Connecting-IP` is set by the edge and a
client cannot forge it; `X-Forwarded-For` is never read. Behind another proxy
(a front Worker that builds new requests, or a non-Cloudflare reverse proxy),
every request may carry the proxy's address and all users share one bucket.
Then pass a `getClientIp` that reads the header *your proxy sets* — never one a
client can send — and consider `requireClientIp: true`.

**`botCheck`** runs on `/email/start` before anything is sent or counted, on
`/email/verify` before any budget, attempt or breaker count is taken, and on
`/pin/login` before any device or PIN work. The second argument says which;
return `true` for an action you do not want to guard. A Turnstile token is
single-use, so guarding both email steps means the page fetches a fresh token
for each. Read the token from the request (a clone) it is given.

**`circuitBreaker`** (off by default): while, within one fixed `windowSec`
window, at least `minFailures` email verifications failed and they are at
least `maxFailureRatio` of all verifications, `/email/verify` answers `503
temporarily_unavailable` *to everyone*. Both numbers count only verifications
that compared a live code, and both live in one row, counted in the same
window. It slows a distributed guessing run, and it also hands whoever can
produce that many failures a switch that turns email login off — set
`minFailures` far above your normal failure volume.

How many IPs that switch takes: each IPv4 address (IPv6: each /64) gets at
most `verifiesPerIpPerHour` verifications per fixed hour, so within a breaker
window of up to an hour it can add at most `2 × verifiesPerIpPerHour`
failures (two hour-windows straddled). Each failure also needs a live code
with attempts left, and `startsPerIpPerHour × 5` (100 by default) is no
tighter. Opening the breaker therefore takes at least
`⌈minFailures / (2 × verifiesPerIpPerHour)⌉` IPs — with the defaults
`⌈minFailures / 120⌉`: 1 IP for `minFailures` ≤ 120, 5 for 600, 9 for
1,000; `⌈minFailures / 60⌉` (10, 17) when nothing straddles an hour. A window
longer than an hour lets each IP add more (`verifiesPerIpPerHour` per started
hour plus one). If client IPs are missing and `requireClientIp` is off, the
per-IP limits are skipped and one client can open it.

Rejected as weak PINs: fewer than 3 distinct digits (`000000`, `101010`,
`100000`), runs including ones that wrap round 9→0 (`123456`, `987654`,
`890123`), palindromes (`123321`), repeated 2- or 3-digit blocks (`121212`,
`123123`), doubled/tripled digits (`112233`, `111222`), two straight keypad
lines (`147258`, `159357`, `123654`), and the 179 six-digit numbers in
SecLists' `10k-most-common.txt` (embedded in the source with its sha256) plus a
few more. SecLists is MIT-licensed; its notice ships in
[`THIRD_PARTY_NOTICES`](./THIRD_PARTY_NOTICES). Dates are refused only with `pin.rejectDateLike`.

### PIN cost: the pepper is what protects a 6-digit PIN

There are only 10^6 PINs. If the credentials table leaks *without* the secret,
nothing can be brute-forced, because every PIN is HMAC'd with a pepper derived
from `secret` before PBKDF2 sees it. If both leak, PBKDF2 barely helps — even
at 100,000 iterations, trying all 10^6 PINs takes seconds to minutes on a single
GPU. **The pepper is the defence; the iteration count is a second line.**

Measured cost of one PBKDF2-SHA256 derivation in workerd (local
`@cloudflare/vitest-pool-workers`, on the development machine — production CPUs
will differ):

| iterations | ms per PIN check |
| --- | --- |
| 100,000 (default) | 146.3 |
| 50,000 | 73.5 |
| 10,000 | 12.3 |

That is well over the Workers **Free plan's 10 ms CPU** limit. **Apps on the
Free plan may lower `pin.iterations`** (minimum 1,000) — it is safe to do so
precisely because the pepper, not the iteration count, is what stands between
a leaked table and the PINs. A PIN is re-hashed at the configured cost on its
next successful login, so the setting can be changed at any time. PBKDF2 only
ever runs for a caller holding a valid trusted device on an unlocked account,
so an unauthenticated caller cannot make the Worker spend it.

### The secret, and rotating it

`secret` is the only key material. HKDF-SHA256 derives an email-code HMAC key
and the PIN pepper from it, plus a public `keyId` stored next to every hash
(`material.pepperVer` for PINs, `key_id` for codes) so each row is verified with
the secret that made it.

`deviceAuth()` refuses a secret shorter than 32 characters, with fewer than 10
distinct characters, or whose character-distribution entropy estimate is below
96 bits (`'a'.repeat(40)`, a word typed four times, `changemechangeme…`). That
check only catches placeholders — it cannot tell a random string from a
well-mixed typed one — so **generate the secret**:

```bash
# generate it yourself and store it as a Worker secret; never commit the value
openssl rand -base64 48
npx wrangler secret put DEVICE_AUTH_SECRET
```

On Windows without OpenSSL:
`[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))`
in PowerShell does the same. For local development put it in `.dev.vars`
(keep `.dev.vars*` gitignored).

Rotation, without logging anyone out:

1. Set the new value as `DEVICE_AUTH_SECRET` and move the old one into
   `DEVICE_AUTH_PREVIOUS_SECRETS` (comma-separated), passed as `previousSecrets`.
2. Deploy. New codes and PINs use the new secret; old ones still verify, and
   each PIN is re-hashed under the new secret on its next successful login.
3. Wait as long as you want returning users to be covered — the device idle
   lifetime (90 days) is a natural bound. Email codes need only 10 minutes.
4. Remove the old secret from `DEVICE_AUTH_PREVIOUS_SECRETS` and deploy.
   PINs that were never re-hashed stop verifying; those users get
   `invalid_pin` and recover with an email code and a new PIN.

If the secret leaked, skip the waiting: rotate without `previousSecrets`, and
every PIN has to be reset via email.

### Adding passkeys later

Login methods are `CredentialKind`s stored in one generic `auth_credentials`
table (`type IN ('pin','passkey')` — `passkey` is in the CHECK already, because
SQLite cannot alter a CHECK without rebuilding the table). Failure counting and
lockout (`auth_login_guards`), trusted devices, device-bound sessions, audit
events and session minting are kind-agnostic. Adding passkeys means adding one
part:

```
   shared, unchanged: auth_login_guards / auth_trusted_devices / onEvent / createSession
                                         ^
              CredentialKind<TInput> { type, requiresTrustedDevice, enroll, verify }
                       +-----------------+------------------+
              pinCredential()                     passkeyCredential()   (later)
              requiresTrustedDevice: true         requiresTrustedDevice: false
              (this release)                      + its own challenge-table migration and routes
```

No existing table, column or route changes. (The part itself — WebAuthn
attestation/assertion verification — is substantial; whether it can keep this
package at zero runtime dependencies is a decision for that time.)

### Cleanup

`d1DeviceAuthStore(db).cleanup(now?, rateLimitHorizonMs?)` deletes expired codes
and devices, revoked devices and credentials, and rate-limit windows that
started more than `rateLimitHorizonMs` ago (default: one day). Run it from a
cron trigger. **If you raise `emailCode.failureWindowSec` above a day, pass a
`rateLimitHorizonMs` at least that long**, or cleanup will forget failures the
cap still needs.

## Layer 4: the client

```ts
import { createAuthClient } from '@tomu-ai/workers-auth/client';

const client = createAuthClient({ baseUrl: '/auth' });

const current = await client.session();   // { user, session } | null
await client.logout();
```

Everything is sent with `credentials: 'include'` and `cache: 'no-store'` — and
the server backs that up with `Cache-Control: no-store, private` on every
response, so nothing between the two can cache an identity response either.
Concurrent `session()` calls share one request; the shared promise is dropped
the moment it settles, so nothing is remembered.

## Non-goals

Deliberately absent, and not up for addition:

- web storage of any kind (`localStorage` / `sessionStorage` / IndexedDB) in
  this SDK's client. (`deviceAuth`'s cross-site mode hands tokens to the app;
  where the app keeps them is the app's decision, not something this package
  does for it.)
- cross-tab state broadcasting
- background token refresh loops
- response caching in the client
- email delivery
- UI components
- multi-tenant (org-level) permission evaluation — `Session.scope` is reserved
  for it but nothing reads it yet

These exist because a previous project had to rip out an SDK over exactly two
bugs: a cached `/token` response and cross-tab storage broadcast races. This
package cannot reproduce either — and the cacheable-response failure mode is
closed on the server side too (see `Cache-Control` above), not left to the
client's discipline alone.

## Migrations

D1 migrations ship in `migrations/`. Apply only what you use:

| file | needed for |
| --- | --- |
| `0001_sessions.sql` | `d1SessionStore` |
| `0002_revocations.sql` | `revocationList` — per-session tombstones |
| `0003_magic_link_tokens.sql` | `d1MagicLinkStore` |
| `0004_api_keys.sql` | `d1ApiKeyStore` |
| `0005_user_revocations.sql` | `revocationList` — "log out everywhere" |
| `0006_device_auth.sql` | `d1DeviceAuthStore` — email codes, trusted devices, credentials, lockout, rate limits |

```bash
npx wrangler d1 migrations apply <db> --local
```

**Postgres:** `migrations/pg/` holds the same files with the same numbers
(times are `BIGINT` milliseconds, counters `INTEGER`, JSON `TEXT`). The stores
need `0001_sessions.sql` and `0006_device_auth.sql`; `0002`–`0005` create the
tables of the D1/KV-only stores so both schemas stay alike. There is no
migration runner on Neon's side — apply them in order with any client, for
example:

```bash
for f in node_modules/@tomu-ai/workers-auth/migrations/pg/000{1,6}_*.sql; do psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"; done
```

For a schema other than `public`, create it and apply with that search path
(table names in the files are unqualified), then pass the same `schema`:

```bash
psql "$DATABASE_URL" -c 'CREATE SCHEMA IF NOT EXISTS workers_auth'
PGOPTIONS='-c search_path=workers_auth' psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f .../0006_device_auth.sql
```

A test (`test/pg/schema.test.ts`) fails if the D1 and Postgres files ever
disagree on a table, column, nullability, primary key or index.

## Testing your integration

### Prefer real KV/D1 over hand-rolled fakes

Test the parts of your app that sit behind `auth.middleware()` /
`auth.routes()` against **real Miniflare KV and D1**
(`@cloudflare/vitest-pool-workers`), not a hand-rolled `Map`-based fake —
even though a fake is faster to write and faster to run.

This isn't a generic "prefer integration tests" recommendation; it's specific
to what this SDK does. `kvSessionStore`'s `touch()`/`revoke()` split exists to
survive a specific KV race (see
[SECURITY.md](./SECURITY.md#fixed-was-p0-touch-could-resurrect-a-revoked-session)),
and its expiry/revocation checks are written the way they are *because* KV's
writes are eventually consistent and its minimum TTL is 60s. A fake that
resolves `put`/`get`/`delete` synchronously against a `Map` cannot reproduce
either property, so a regression in this exact area — the one this SDK has
already shipped and fixed a P0 for once — is precisely the kind of bug such a
fake would pass and real KV would catch. `d1SessionStore`'s single-statement
`DELETE ... RETURNING` for atomic magic-link consumption has the same
relationship to a fake D1: the atomicity is the whole point, and a fake that
just runs your mock function synchronously can't exercise it.

If your own application logic (not the auth layer) has no such properties to
get wrong, a fake is a reasonable choice for *that* code — this
recommendation is about whatever touches `SessionStore`, `RevocationList`, or
`ApiKeyStore`/`MagicLinkStore`, not a blanket rule for your whole test suite.

### `@tomu-ai/workers-auth/testing`

Cookie-session tests all need the same shape: log in, capture the
`Set-Cookie` headers, replay them as a `Cookie` header on the next request.
This subpath exists so that shape doesn't get re-derived — slightly
differently, with slightly different gaps — in every project that adopts
this SDK.

```ts
import { cookieHeader, loginForCookies, readCookieJar } from '@tomu-ai/workers-auth/testing';

// Build whatever Request satisfies your configured AuthProvider — an
// Authorization header for apiKey/neonAuth, a magic-link token, a test
// double's own header. loginForCookies just needs a 200 back.
const jar = await loginForCookies(
  (req) => app.fetch(req, env),
  new Request('https://example.com/auth/session', {
    method: 'POST',
    headers: { origin: 'https://example.com', authorization: `Bearer ${testApiKey}` },
  }),
);

const res = await app.fetch(
  new Request('https://example.com/api/me', { headers: { cookie: cookieHeader(jar) } }),
  env,
);
```

`readCookieJar` and `cookieHeader` don't assume any particular cookie name or
prefix — `cookie: { name, csrfName, prefix }` is configurable per
`createAuth()` call, so they read back whatever names the server actually
sent rather than hardcoding `__Host-session`/`__Host-csrf`. If a test needs a
specific cookie's raw value (e.g. to assert it never appears in a response
body), index the jar by the same name you configured:
`jar['__Host-session']`, or whatever `cookie.name` resolves to.

Nothing else about your `AuthProvider`, your routes, or your business logic
is assumed — this subpath only knows about cookies and, below, about the
shape of a delivered email. It has no dependency on Hono and no Node
builtins, so it's safe to import from a test that runs inside
`@cloudflare/vitest-pool-workers`' workerd pool.

#### Magic-link flows

A magic-link E2E test has one extra step the cookie helpers can't cover: the
token arrives out of band, in an email. `waitForEmail` and
`extractMagicLinkFromEmail` cover that step without this package learning
anything about email — the same reason `magicLink()` takes a `sendToken`
callback instead of an SMTP client.

`waitForEmail` takes **your** "list the mail that has arrived" function. Resend,
Mailtrap, SES, a local catch-all inbox — whichever you use stays on your side of
the callback, and this SDK keeps its zero runtime dependencies:

```ts
import {
  cookieHeader,
  extractMagicLinkFromEmail,
  loginForCookies,
  waitForEmail,
} from '@tomu-ai/workers-auth/testing';
import type { EmailLike } from '@tomu-ai/workers-auth/testing';

// Whatever your provider's "list recent messages" call looks like. Map it once,
// into the minimal { to, subject, html?, text?, createdAt? } shape.
const fetchEmails = async (): Promise<EmailLike[]> => {
  const res = await fetch('https://api.example-mail.test/messages', {
    headers: { authorization: `Bearer ${env.MAIL_API_KEY}` },
  });
  const { data } = (await res.json()) as { data: EmailLike[] };
  return data;
};

// 1. Trigger the send.
await app.fetch(
  new Request('https://example.com/auth/magic-link', {
    method: 'POST',
    headers: { origin: 'https://example.com', 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'user@example.com' }),
  }),
  env,
);

// 2. Wait for it to land. Polls immediately, then every intervalMs (default
//    500ms) until timeoutMs (default 10_000ms).
const email = await waitForEmail(
  fetchEmails,
  (m) => m.to === 'user@example.com' && m.subject.includes('Sign in'),
  { timeoutMs: 15_000, intervalMs: 250 },
);

// 3. Pull the link out and consume it.
const link = extractMagicLinkFromEmail(email.html ?? email.text ?? '');
const token = new URL(link).searchParams.get('token')!;

const jar = await loginForCookies(
  (req) => app.fetch(req, env),
  new Request('https://example.com/auth/session', {
    method: 'POST',
    headers: { origin: 'https://example.com', 'x-magic-token': token },
  }),
);

const me = await app.fetch(
  new Request('https://example.com/api/me', { headers: { cookie: cookieHeader(jar) } }),
  env,
);
```

A real template holds more than one URL — a logo, a help link, an unsubscribe
footer — so `extractMagicLinkFromEmail` doesn't take the first match. It ranks
every `http(s)` URL in the body and returns the best one: a token-ish query
parameter first (`token`, `magic_token`, `magicToken`, `verify-token`,
`magiclink` — case and `-`/`_` are normalised away), then an auth-looking path
for `/verify/<token>` style links, then document order. It also decodes `&amp;`,
which is how an HTML body spells `&`, and trims trailing sentence punctuation
off a plain-text link.

If your links don't look like that, replace the scan outright:

```ts
// A custom scheme, a token in an attribute, a host that must match exactly —
// options.pattern is used as-is, and capture group 1 wins if the pattern has one.
extractMagicLinkFromEmail(email.html!, { pattern: /href="(https:\/\/app\.example\.com\/go\?[^"]+)"/ });
```

Both helpers throw rather than returning `null` or `undefined`: a test can't
continue without the link, and the messages name what was searched — the body
length for a failed extraction, the poll count and the size of the last fetch
for a timeout. That last pair separates the two failures that otherwise look
identical: `last fetch returned 0 email(s)` means nothing was delivered (look at
the sending side), while a non-zero count means mail arrived but your predicate
never matched (look at the subject or recipient you're matching on).

`waitForEmail` sleeps via the global `setTimeout` and measures with `Date.now()`,
so vitest's fake timers drive it and your suite doesn't spend the real timeout
waiting:

```ts
vi.useFakeTimers();
const pending = waitForEmail(fetchEmails, (m) => m.to === 'user@example.com');
await vi.advanceTimersByTimeAsync(500); // second poll
await expect(pending).resolves.toMatchObject({ to: 'user@example.com' });
```

#### Email-code flows (`deviceAuth`)

Same shape, one helper different: `extractEmailCodeFromEmail(body)` returns the
6-digit code (`{ digits: 8 }` for `emailCode.digits: 8`). It strips `<style>`/`<script>` blocks and tags first, ignores
digits that are part of a longer number or a `#123456` colour, and **throws if
more than one distinct 6-digit number is left** (an order number in the footer,
say) rather than guess — pass `{ pattern }` to point at the code exactly.

```ts
import { extractEmailCodeFromEmail, waitForEmail } from '@tomu-ai/workers-auth/testing';

const email = await waitForEmail(fetchEmails, (m) => m.to === 'user@example.com');
const code = extractEmailCodeFromEmail(email.text ?? email.html ?? '');
// POST /auth/device/email/verify { email: 'user@example.com', code }
```

In `transport: 'cookie'` mode the device cookie arrives in `Set-Cookie` like the
session cookie, so `readCookieJar` / `cookieHeader` carry it forward unchanged.
In `'response'` mode, read `deviceToken` / `sessionToken` from the JSON body and
send them back as `x-device-token` / `Authorization: Bearer`.

### D1 migrations in your own test suite

The migrations in [Migrations](#migrations) above ship inside the published
package (`node_modules/@tomu-ai/workers-auth/migrations`), so a consumer test
suite that uses `d1SessionStore` / `revocationList` / `d1MagicLinkStore` /
`d1ApiKeyStore` can apply them the same way this SDK applies them to its own
tests, without vendoring a copy:

```ts
// vitest.config.ts
import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const migrations = await readD1Migrations(
  fileURLToPath(new URL('./node_modules/@tomu-ai/workers-auth/migrations', import.meta.url)),
);

export default defineConfig({
  plugins: [
    cloudflareTest({
      singleWorker: true,
      miniflare: {
        compatibilityDate: '2025-04-01',
        kvNamespaces: ['KV'],
        d1Databases: ['DB'],
        bindings: { TEST_MIGRATIONS: migrations },
      },
    }),
  ],
  test: { setupFiles: ['./test/apply-migrations.ts'] },
});
```

```ts
// test/apply-migrations.ts — runs once per test file
import { applyD1Migrations, env } from 'cloudflare:test';

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
```

`readD1Migrations` and `applyD1Migrations` are `@cloudflare/vitest-pool-workers`'s
own exports, not this SDK's — there's nothing SDK-specific to wrap here beyond
pointing them at the bundled `migrations/` directory. If your app also has its
own migrations, apply both directories in `apply-migrations.ts`.

## Development

```bash
pnpm install
pnpm typecheck
pnpm pg:up       # Docker: postgres:17 + a local Neon HTTP proxy (random password in test/pg/.env)
pnpm test        # all three vitest projects, one after another (below)
pnpm test:d1     # D1 only — no Docker needed
pnpm pg:down     # stop Postgres and delete its data and password file
pnpm build       # tsup, ESM + d.ts
```

Three vitest projects: **d1** (everything, on workerd with Miniflare KV/D1),
**pg** (the `deviceAuth` suites and the store contract again, on workerd,
against Postgres through `@neondatabase/serverless` and the local proxy) and
**pg-node** (Node + `pg`: row-lock interleavings on two held-open connections,
which an HTTP driver cannot do). Without `pnpm pg:up` the pg projects fail with
a message saying so; they never skip.

`pnpm test:neon` runs the same Postgres suites against a real Neon project
instead, reading a direct (non-pooler) connection string from
`test/pg/.env.neon` (`NEON_TEST_DATABASE_URL=...`, gitignored). Only that
command targets Neon — plain `pnpm test` never reads the file — and it first
refuses, before truncating or creating anything, any database that holds a
table or view other than `auth_*`: point it at a dedicated test project only.

Tests run on real Miniflare KV and D1. The `deviceAuth` suites use 1,000 PBKDF2
iterations to stay fast; one test exercises the 100,000 default end to end. Stores, providers and `createAuth` all
accept a `clock` option so expiry behaviour is tested deterministically instead
of with sleeps. Several tests wrap KV in a gate that can hold a `put` open, so
races (a `touch()` in flight against a concurrent `revoke()`, two requests
consuming the same magic-link token) are reproduced directly instead of
inferred from code review.

See [SECURITY.md](./SECURITY.md) for the security defaults and their rationale.

## Status

`0.1.0`. The version stays at `0.1.x` until it has been proven in a real
project.
