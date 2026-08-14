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
    store: kvSessionStore(c.env.KV),
    cookie: { prefix: '__Host-', name: 'session' },
    session: { idleTtlSec: 60 * 60 * 24 * 7, absoluteTtlSec: 60 * 60 * 24 * 30 },
  });
  c.set('auth', auth);
  return next();
});
```

Bindings only exist per request in Workers, so `createAuth` is called per
request. It allocates nothing expensive: the JWKS cache lives at module scope and
survives across requests inside the isolate.

If your bindings come from a module-scope `env` instead, build the instance once
and reuse it:

```ts
const auth = createAuth({ providers: [...], store: kvSessionStore(env.KV) });

app.use('/api/*', auth.middleware());
app.route('/auth', auth.routes());
app.get('/api/me', (c) => c.json(getUser(c)));
```

### What `auth.routes()` mounts

| method | path | behaviour |
| --- | --- | --- |
| `POST` | `/session` | run providers → mint session → set cookies |
| `GET` | `/session` | current session, or 401 |
| `POST` | `/logout` | revoke session + clear cookies |
| `GET` | `/callback` | magic-link landing → mint session → 302 |

`POST /session` and `POST /logout` require an `Origin` header. Browsers always
send one; a server-side caller must set it explicitly.

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

`c.get('user')` is typed through Hono's `ContextVariableMap`. The cookie session
itself is on `c.get('authSession')` (or `getSession(c)`), and is `null` when the
subject authenticated with a bearer credential instead.

## Layer 1: session stores

### `kvSessionStore(namespace, options?)` — default

Keys are `sess:<sha256(sid)>`, plus a `uidx:<userId>:<sha256(sid)>` reverse index
that powers `revokeAllForUser`. `expirationTtl` is set from the absolute expiry,
but both expiries are also checked in code on every read — KV's 60s minimum TTL
and eventually-consistent deletes make the TTL garbage collection, not access
control.

### `d1SessionStore(db, options?)`

Strongly consistent, so revocation is immediate. Costs one D1 read per
authenticated request. Exposes an extra `cleanup(now?)` for a cron trigger.
Apply `migrations/0001_sessions.sql` first.

### `revocationList(d1, options?)` — KV + immediate revocation

KV's eventual consistency means a logged-out session can keep working for up to
about a minute. When that is unacceptable, keep KV as the primary store and put
the tombstones in D1:

```ts
import { kvSessionStore } from '@tomu-ai/workers-auth/store/kv';
import { revocationList } from '@tomu-ai/workers-auth/store/d1';

const store = kvSessionStore(env.KV, { revocation: revocationList(env.DB) });
```

`revoke()` writes `sha256(sid)` to `auth_revocations`; `get()` spends one D1
query checking it. Without the option, no D1 query is made at all — that is the
latency-first choice for lightweight apps. `revocationList(...).cleanup()`
deletes tombstones whose session would have expired anyway.

## Layer 2: providers

Providers are tried in array order and the first success wins. Provider-specific
values live in `AuthUser.claims`, never on the top level — that is what keeps
providers swappable.

### `neonAuth({ jwksUrl, issuer, audience })`

JWKS verification for RS256 / ES256 / EdDSA (RS384, RS512 and ES384 are also
available via `algorithms`). `iss`, `aud`, `exp` and `nbf` are all enforced.
The JWKS is cached at module scope and optionally in KV (`cache: { kv }`). An
unknown `kid` triggers exactly one refetch, rate limited to one network call per
`minRefetchIntervalSec` (default 60), so key rotation is picked up without
turning the endpoint into an amplifier.

### `magicLink({ store, sendToken, ttlSec })`

**This SDK does not send email.** Inject the sender:

```ts
import { magicLink, d1MagicLinkStore } from '@tomu-ai/workers-auth/magic-link';

const provider = magicLink({
  store: d1MagicLinkStore(env.DB),
  ttlSec: 900,
  sendToken: async (email, token) => {
    await sendWithYourProvider(email, `https://app.example.com/auth/callback?token=${token}`);
  },
  resolveUser: async (email) => lookupUser(email),   // optional; default id = email
});

await provider.start('user@example.com');            // always returns { ok: true }
```

Tokens are 256-bit, stored as SHA-256, and single-use. `d1MagicLinkStore`
consumes them with `DELETE ... RETURNING`, which makes single-use atomic;
`kvMagicLinkStore` cannot promise that under a race. `start()` does identical
work for every address and swallows delivery errors into `onSendError`, so it
cannot be used to enumerate accounts. Rate limiting `start()` is your job.

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

Everything is sent with `credentials: 'include'` and `cache: 'no-store'`.
Concurrent `session()` calls share one request; the shared promise is dropped the
moment it settles, so nothing is remembered.

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
package cannot reproduce either.

## Migrations

D1 migrations ship in `migrations/`. Apply only what you use:

| file | needed for |
| --- | --- |
| `0001_sessions.sql` | `d1SessionStore` |
| `0002_revocations.sql` | `revocationList` |
| `0003_magic_link_tokens.sql` | `d1MagicLinkStore` |
| `0004_api_keys.sql` | `d1ApiKeyStore` |

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
of with sleeps.

See [SECURITY.md](./SECURITY.md) for the security defaults and their rationale.

## Status

`0.1.0`. The version stays at `0.1.x` until it has been proven in a real
project.
