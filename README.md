# @tomu-ai/workers-auth

Auth session management for Cloudflare Workers + Hono. Zero runtime dependencies
(Web Crypto only), ESM only, Node 20+.

**The client is deliberately thin and the server holds all state.** No web
storage, no cross-tab broadcast, no background refresh loop. That is a hard
design constraint, not a default — see [Non-goals](#non-goals).

```
Layer 1  SessionStore   persistence        kv / d1 / + revocation list
Layer 2  AuthProvider   identity proof     neon / magic-link / api-key
Layer 3  middleware     Hono integration   auth.middleware(), auth.routes()
Layer 4  client         browser            createAuthClient()
```

## Install

```bash
pnpm add @tomu-ai/workers-auth hono
```

Subpaths are split so a project that only wants sessions does not pull in JWKS
verification or D1 code:

| import | contents |
| --- | --- |
| `@tomu-ai/workers-auth` | `createAuth`, middleware, routes, types, crypto/cookie/csrf helpers |
| `@tomu-ai/workers-auth/store/kv` | `kvSessionStore` |
| `@tomu-ai/workers-auth/store/d1` | `d1SessionStore`, `revocationList` |
| `@tomu-ai/workers-auth/neon` | `neonAuth`, `clearJwksCache` |
| `@tomu-ai/workers-auth/magic-link` | `magicLink`, `kvMagicLinkStore`, `d1MagicLinkStore` |
| `@tomu-ai/workers-auth/api-key` | `apiKey`, `issueApiKey`, `kvApiKeyStore`, `d1ApiKeyStore` |
| `@tomu-ai/workers-auth/client` | `createAuthClient` |

## Choosing a session store

Three configurations, three different guarantees. Pick the row that matches
what you actually need — going further than that only adds a D1 dependency for
no benefit.

| configuration | login / logout | revoke one session | log out everywhere |
| --- | --- | --- | --- |
| `kvSessionStore({ allowUnrevocableSessions: true })` | ✅ | ✅ (up to ~60s to propagate) | ❌ — no-op |
| `kvSessionStore({ revocation })` | ✅ | ✅ immediate | ✅ |
| `d1SessionStore()` | ✅ | ✅ immediate | ✅ |

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

## Minimal setup

```ts
import { Hono } from 'hono';
import { createAuth, getUser } from '@tomu-ai/workers-auth';
import { kvSessionStore } from '@tomu-ai/workers-auth/store/kv';
import { neonAuth } from '@tomu-ai/workers-auth/neon';

type Env = { KV: KVNamespace; NEON_JWKS_URL: string };

const app = new Hono<{ Bindings: Env }>();

app.use('*', async (c, next) => {
  const auth = createAuth({
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
  });
  c.set('auth', auth);
  return next();
});
```

Bindings only exist per request in Workers, so `createAuth` is called per
request above. It allocates nothing expensive: the JWKS cache lives at module
scope and survives across requests inside the isolate.

If your bindings come from a module-scope `env` instead, build the instance once
and reuse it:

```ts
const auth = createAuth({ providers: [...], store: kvSessionStore(env.KV, { allowUnrevocableSessions: true }) });

app.use('/api/*', auth.middleware());
app.route('/auth', auth.routes());
app.get('/api/me', (c) => c.json(getUser(c)));
```

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
the worst time to discover a missing dependency for the first time. See
[Choosing a session store](#choosing-a-session-store).

### `d1SessionStore(db, options?)`

Strongly consistent, so revocation — including `revokeAllForUser()` — is
immediate and needs no extra table. Costs one D1 read per authenticated
request. Exposes an extra `cleanup(now?)` for a cron trigger. Apply
`migrations/0001_sessions.sql` first.

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

## Layer 2: providers

Providers are tried in array order and the first success wins. Provider-specific
values live in `AuthUser.claims`, never on the top level — that is what keeps
providers swappable.

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

- web storage of any kind (`localStorage` / `sessionStorage` / IndexedDB)
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

```bash
npx wrangler d1 migrations apply <db> --local
```

## Development

```bash
pnpm install
pnpm typecheck
pnpm test        # vitest + @cloudflare/vitest-pool-workers (runs on workerd)
pnpm build       # tsup, ESM + d.ts
```

Tests run on real Miniflare KV and D1. Stores, providers and `createAuth` all
accept a `clock` option so expiry behaviour is tested deterministically instead
of with sleeps. Several tests wrap KV in a gate that can hold a `put` open, so
races (a `touch()` in flight against a concurrent `revoke()`, two requests
consuming the same magic-link token) are reproduced directly instead of
inferred from code review.

See [SECURITY.md](./SECURITY.md) for the security defaults and their rationale.

## Status

`0.1.0`. The version stays at `0.1.x` until it has been proven in a real
project.
