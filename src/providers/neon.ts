/**
 * Neon Auth (Stack Auth) JWT provider — JWKS verification on Web Crypto.
 *
 * Hardening notes:
 *  - the algorithm allow-list is applied to the *header* before any key lookup,
 *    so `none` and HMAC confusion attacks die immediately;
 *  - the JWK is rebuilt from scratch (kty/crv/n/e/x/y only) before import, so a
 *    hostile JWKS cannot smuggle `key_ops` / `alg` tricks past WebCrypto;
 *  - the key type must match the header algorithm;
 *  - an unknown `kid` triggers exactly one refetch, rate limited, so key
 *    rotation is picked up without turning the endpoint into a DoS amplifier.
 */

import { base64urlDecode, base64urlDecodeToString, sha256Hex } from '../crypto.js';
import type { AuthProvider, AuthUser, Clock } from '../types.js';

export type JwsAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'EdDSA';

export type Jwk = {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  crv?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
};

export type NeonAuthOptions = {
  jwksUrl: string;
  /** Expected `iss`. Compared exactly. */
  issuer: string;
  /** Expected `aud`. A token matching any listed audience passes. */
  audience: string | string[];
  /** Allowed signature algorithms. Default: RS256 / ES256 / EdDSA. */
  algorithms?: JwsAlgorithm[];
  /**
   * Leeway for exp/nbf, in seconds. Default: 30.
   *
   * Zero tolerance turns ordinary clock drift between the issuer and the edge
   * into sporadic 401s that are miserable to diagnose. 30s absorbs that drift
   * while keeping the extra validity an expired token gets away with short —
   * see SECURITY.md for the tradeoff. Callers can override in either
   * direction.
   */
  clockToleranceSec?: number;
  /** How long a fetched JWKS stays fresh. Default: 600s. */
  jwksCacheTtlSec?: number;
  /** Minimum gap between JWKS network fetches. Default: 60s. */
  minRefetchIntervalSec?: number;
  /** Abort a JWKS fetch after this long. Default: 3000ms. */
  fetchTimeoutMs?: number;
  /** Reject a JWKS document larger than this. Default: 262144 (256KB). */
  maxJwksBytes?: number;
  /** Reject a JWKS document with more keys than this. Default: 32. */
  maxJwksKeys?: number;
  /** Second-tier JWKS cache, shared across isolates. */
  cache?: { kv: KVNamespace; keyPrefix?: string };
  /** Override how the bearer token is located. Default: `Authorization: Bearer`. */
  getToken?: (req: Request) => string | null;
  /** Injectable fetch, for tests and for custom retry/proxy behaviour. */
  fetchImpl?: typeof fetch;
  clock?: Clock;
  /** Provider name, surfaced on `AuthUser.claims.provider`. Default: `neon`. */
  name?: string;
};

const DEFAULT_ALGORITHMS: JwsAlgorithm[] = ['RS256', 'ES256', 'EdDSA'];
const MAX_TOKEN_BYTES = 8192;

type CacheEntry = {
  keys: Jwk[];
  fetchedAt: number;
  lastAttemptAt: number;
  imported: Map<string, CryptoKey>;
  inflight?: Promise<Jwk[]>;
};

/** Module-scope tier of the two-tier JWKS cache. Survives across requests. */
const jwksCache = new Map<string, CacheEntry>();

/** Drops the in-isolate JWKS cache. Exposed for tests and emergency rotation. */
export function clearJwksCache(jwksUrl?: string): void {
  if (jwksUrl) jwksCache.delete(jwksUrl);
  else jwksCache.clear();
}

function entryFor(url: string): CacheEntry {
  let entry = jwksCache.get(url);
  if (!entry) {
    entry = { keys: [], fetchedAt: 0, lastAttemptAt: 0, imported: new Map() };
    jwksCache.set(url, entry);
  }
  return entry;
}

function defaultGetToken(req: Request): string | null {
  const header = req.headers.get('authorization');
  if (!header) return null;
  const match = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/.exec(header.trim());
  return match?.[1] ?? null;
}

type JwtHeader = { alg?: string; kid?: string; typ?: string };
type JwtPayload = Record<string, unknown>;

type DecodedJwt = {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Uint8Array;
  signedData: Uint8Array;
};

function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  if (!h || !p || !s) return null;
  try {
    const header = JSON.parse(base64urlDecodeToString(h)) as JwtHeader;
    const payload = JSON.parse(base64urlDecodeToString(p)) as JwtPayload;
    if (typeof header !== 'object' || header === null) return null;
    if (typeof payload !== 'object' || payload === null) return null;
    return {
      header,
      payload,
      signature: base64urlDecode(s),
      signedData: new TextEncoder().encode(`${h}.${p}`),
    };
  } catch {
    return null;
  }
}

type ImportAlgorithm = { name: string; hash?: string; namedCurve?: string };
type VerifyAlgorithm = { name: string; hash?: string };

type AlgSpec = {
  importAlgorithm: () => ImportAlgorithm;
  verifyAlgorithm: () => VerifyAlgorithm;
  kty: string;
  crv?: string;
};

const ALG_SPECS: Record<JwsAlgorithm, AlgSpec> = {
  RS256: {
    kty: 'RSA',
    importAlgorithm: () => ({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }),
    verifyAlgorithm: () => ({ name: 'RSASSA-PKCS1-v1_5' }),
  },
  RS384: {
    kty: 'RSA',
    importAlgorithm: () => ({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }),
    verifyAlgorithm: () => ({ name: 'RSASSA-PKCS1-v1_5' }),
  },
  RS512: {
    kty: 'RSA',
    importAlgorithm: () => ({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }),
    verifyAlgorithm: () => ({ name: 'RSASSA-PKCS1-v1_5' }),
  },
  ES256: {
    kty: 'EC',
    crv: 'P-256',
    importAlgorithm: () => ({ name: 'ECDSA', namedCurve: 'P-256' }),
    verifyAlgorithm: () => ({ name: 'ECDSA', hash: 'SHA-256' }),
  },
  ES384: {
    kty: 'EC',
    crv: 'P-384',
    importAlgorithm: () => ({ name: 'ECDSA', namedCurve: 'P-384' }),
    verifyAlgorithm: () => ({ name: 'ECDSA', hash: 'SHA-384' }),
  },
  EdDSA: {
    kty: 'OKP',
    crv: 'Ed25519',
    importAlgorithm: () => ({ name: 'Ed25519' }),
    verifyAlgorithm: () => ({ name: 'Ed25519' }),
  },
};

/** Rebuilds a minimal JWK so nothing extra from the wire reaches WebCrypto. */
function sanitizeJwk(jwk: Jwk, alg: JwsAlgorithm): Jwk | null {
  const spec = ALG_SPECS[alg];
  if (jwk.kty !== spec.kty) return null;
  if (jwk.alg && jwk.alg !== alg) return null;
  if (jwk.use && jwk.use !== 'sig') return null;
  if (spec.crv && jwk.crv !== spec.crv) return null;

  if (spec.kty === 'RSA') {
    if (!jwk.n || !jwk.e) return null;
    return { kty: 'RSA', n: jwk.n, e: jwk.e };
  }
  if (spec.kty === 'EC') {
    if (!jwk.x || !jwk.y || !jwk.crv) return null;
    return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  }
  if (!jwk.x || !jwk.crv) return null;
  return { kty: 'OKP', crv: jwk.crv, x: jwk.x };
}

async function importJwk(jwk: Jwk, alg: JwsAlgorithm): Promise<CryptoKey | null> {
  const sanitized = sanitizeJwk(jwk, alg);
  if (!sanitized) return null;
  const spec = ALG_SPECS[alg];
  try {
    return await crypto.subtle.importKey(
      'jwk',
      sanitized as JsonWebKey,
      spec.importAlgorithm() as SubtleCryptoImportKeyAlgorithm,
      false,
      ['verify'],
    );
  } catch {
    if (alg === 'EdDSA') {
      // Older workerd builds only know the pre-standard name.
      try {
        return await crypto.subtle.importKey(
          'jwk',
          sanitized as JsonWebKey,
          { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as unknown as SubtleCryptoImportKeyAlgorithm,
          false,
          ['verify'],
        );
      } catch {
        return null;
      }
    }
    return null;
  }
}

function asAudienceList(aud: unknown): string[] {
  if (typeof aud === 'string') return [aud];
  if (Array.isArray(aud)) return aud.filter((v): v is string => typeof v === 'string');
  return [];
}

export function neonAuth(options: NeonAuthOptions): AuthProvider {
  const {
    jwksUrl,
    issuer,
    audience,
    algorithms = DEFAULT_ALGORITHMS,
    clockToleranceSec = 30,
    jwksCacheTtlSec = 600,
    minRefetchIntervalSec = 60,
    fetchTimeoutMs = 3000,
    maxJwksBytes = 256 * 1024,
    maxJwksKeys = 32,
    cache,
    getToken = defaultGetToken,
    fetchImpl,
    clock = Date.now,
    name = 'neon',
  } = options;

  if (!jwksUrl || !issuer || !audience) {
    throw new TypeError('neonAuth: jwksUrl, issuer and audience are required');
  }
  if (algorithms.length === 0) {
    throw new TypeError('neonAuth: at least one algorithm must be allowed');
  }
  const allowed = new Set<string>(algorithms);
  const expectedAudiences = new Set(asAudienceList(audience));
  const doFetch: typeof fetch = fetchImpl ?? ((input, init) => fetch(input as RequestInfo, init));

  async function kvCacheKey(): Promise<string> {
    return `${cache?.keyPrefix ?? 'jwks:'}${await sha256Hex(jwksUrl)}`;
  }

  async function fetchJwks(entry: CacheEntry): Promise<Jwk[]> {
    if (entry.inflight) return entry.inflight;
    const inflight = (async () => {
      entry.lastAttemptAt = clock();

      // A hung or oversized JWKS endpoint must not become an outage here: no
      // timeout means every authenticated request waits on it, and an unbounded
      // body means it can exhaust the isolate.
      const init: { headers: Record<string, string>; signal?: AbortSignal } = {
        headers: { accept: 'application/json' },
      };
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
        init.signal = AbortSignal.timeout(fetchTimeoutMs);
      }

      const res = await doFetch(jwksUrl, init);
      if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);

      const contentType = res.headers.get('content-type') ?? '';
      if (!contentType.includes('json')) {
        throw new Error(`jwks fetch returned ${contentType || 'no content-type'}`);
      }
      const declaredLength = Number(res.headers.get('content-length') ?? '0');
      if (declaredLength > maxJwksBytes) {
        throw new Error(`jwks document too large: ${declaredLength} bytes`);
      }

      const text = await res.text();
      if (text.length > maxJwksBytes) {
        throw new Error(`jwks document too large: ${text.length} bytes`);
      }

      const body = JSON.parse(text) as { keys?: unknown };
      const keys = Array.isArray(body.keys)
        ? (body.keys.filter((k) => typeof k === 'object' && k !== null) as Jwk[])
        : [];
      if (keys.length > maxJwksKeys) {
        throw new Error(`jwks document has too many keys: ${keys.length}`);
      }
      entry.keys = keys;
      entry.fetchedAt = clock();
      entry.imported.clear();
      if (cache) {
        await cache.kv.put(
          await kvCacheKey(),
          JSON.stringify({ keys, fetchedAt: entry.fetchedAt }),
          { expirationTtl: Math.max(60, jwksCacheTtlSec) },
        );
      }
      return keys;
    })().finally(() => {
      entry.inflight = undefined;
    });
    entry.inflight = inflight;
    return inflight;
  }

  async function loadKeys(entry: CacheEntry): Promise<Jwk[]> {
    const at = clock();
    if (entry.keys.length > 0 && at - entry.fetchedAt < jwksCacheTtlSec * 1000) {
      return entry.keys;
    }
    if (cache) {
      const cached = await cache.kv.get<{ keys: Jwk[]; fetchedAt: number }>(await kvCacheKey(), 'json');
      if (cached && Array.isArray(cached.keys) && at - cached.fetchedAt < jwksCacheTtlSec * 1000) {
        entry.keys = cached.keys;
        entry.fetchedAt = cached.fetchedAt;
        entry.imported.clear();
        return entry.keys;
      }
    }
    return fetchJwks(entry);
  }

  async function resolveKey(kid: string | undefined, alg: JwsAlgorithm): Promise<CryptoKey | null> {
    const entry = entryFor(jwksUrl);
    const cacheKey = `${kid ?? ''}|${alg}`;
    const cached = entry.imported.get(cacheKey);
    if (cached) return cached;

    const pick = (keys: Jwk[]): Jwk | undefined =>
      kid ? keys.find((k) => k.kid === kid) : keys.find((k) => k.kty === ALG_SPECS[alg].kty);

    let keys = await loadKeys(entry);
    let jwk = pick(keys);

    if (!jwk) {
      // Unknown kid: the issuer may have rotated. Refetch exactly once, and
      // only if we have not just hit the endpoint.
      const at = clock();
      if (at - entry.lastAttemptAt < minRefetchIntervalSec * 1000) return null;
      keys = await fetchJwks(entry);
      jwk = pick(keys);
      if (!jwk) return null;
    }

    const key = await importJwk(jwk, alg);
    if (key) entry.imported.set(cacheKey, key);
    return key;
  }

  return {
    name,

    async verify(req: Request): Promise<AuthUser | null> {
      const token = getToken(req);
      if (!token || token.length > MAX_TOKEN_BYTES) return null;

      const decoded = decodeJwt(token);
      if (!decoded) return null;

      const alg = decoded.header.alg;
      if (!alg || !allowed.has(alg) || !(alg in ALG_SPECS)) return null;
      const algorithm = alg as JwsAlgorithm;

      let key: CryptoKey | null;
      try {
        key = await resolveKey(decoded.header.kid, algorithm);
      } catch {
        return null; // JWKS unreachable: fail closed, never fall through
      }
      if (!key) return null;

      const spec = ALG_SPECS[algorithm];
      let valid = false;
      try {
        valid = await crypto.subtle.verify(
          spec.verifyAlgorithm() as SubtleCryptoSignAlgorithm,
          key,
          decoded.signature as unknown as BufferSource,
          decoded.signedData as unknown as BufferSource,
        );
      } catch {
        return null;
      }
      if (!valid) return null;

      const { payload } = decoded;
      const skew = clockToleranceSec * 1000;
      const at = clock();

      if (payload['iss'] !== issuer) return null;

      const aud = asAudienceList(payload['aud']);
      if (aud.length === 0 || !aud.some((a) => expectedAudiences.has(a))) return null;

      const exp = payload['exp'];
      if (typeof exp !== 'number' || at > exp * 1000 + skew) return null;

      const nbf = payload['nbf'];
      if (nbf !== undefined) {
        if (typeof nbf !== 'number' || at < nbf * 1000 - skew) return null;
      }

      const sub = payload['sub'];
      if (typeof sub !== 'string' || sub.length === 0) return null;

      const email = payload['email'];

      return {
        id: sub,
        subjectType: 'user',
        ...(typeof email === 'string' ? { email } : {}),
        claims: { ...payload, provider: name },
      };
    },
  };
}
