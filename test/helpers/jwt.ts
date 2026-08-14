import { base64urlEncode } from '../../src/crypto.js';
import type { Jwk } from '../../src/providers/neon.js';

export type TestKey = {
  kid: string;
  alg: 'RS256' | 'ES256';
  privateKey: CryptoKey;
  jwk: Jwk;
};

const encoder = new TextEncoder();

function encodeSegment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

export async function generateKey(alg: 'RS256' | 'ES256', kid: string): Promise<TestKey> {
  const algorithm =
    alg === 'RS256'
      ? {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        }
      : { name: 'ECDSA', namedCurve: 'P-256' };

  const pair = (await crypto.subtle.generateKey(algorithm as never, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const exported = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Jwk;
  const jwk: Jwk = { ...exported, kid, alg, use: 'sig' };
  delete (jwk as Record<string, unknown>)['key_ops'];
  delete (jwk as Record<string, unknown>)['ext'];

  return { kid, alg, privateKey: pair.privateKey, jwk };
}

export async function signJwt(
  key: TestKey,
  payload: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const header = { alg: key.alg, kid: key.kid, typ: 'JWT', ...headerOverrides };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;

  const signAlgorithm =
    key.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };

  const signature = await crypto.subtle.sign(
    signAlgorithm as never,
    key.privateKey,
    encoder.encode(signingInput),
  );

  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

/** A counting fake JWKS endpoint. */
export function jwksFetch(keys: Jwk[]) {
  const state = { calls: 0, keys };
  const impl = (async () =>
    new Response(JSON.stringify({ keys: state.keys }), {
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;

  const counting = ((input: unknown, init: unknown) => {
    state.calls += 1;
    return (impl as (a: unknown, b: unknown) => Promise<Response>)(input, init);
  }) as unknown as typeof fetch;

  return { fetchImpl: counting, state };
}

export function bearer(token: string, url = 'https://app.example.com/api/me'): Request {
  return new Request(url, { headers: { authorization: `Bearer ${token}` } });
}
