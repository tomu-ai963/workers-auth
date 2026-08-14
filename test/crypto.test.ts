import { describe, expect, it } from 'vitest';

import {
  base64urlDecode,
  base64urlDecodeToString,
  base64urlEncode,
  fingerprint,
  randomBytes,
  randomToken,
  secretEquals,
  sha256Hex,
  timingSafeEqual,
  verifySecretHash,
} from '../src/crypto.js';

describe('crypto', () => {
  it('mints 256-bit base64url tokens', () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(base64urlDecode(token).length).toBe(32);
  });

  it('does not repeat tokens', () => {
    const seen = new Set(Array.from({ length: 200 }, () => randomToken()));
    expect(seen.size).toBe(200);
  });

  it('rejects nonsense lengths', () => {
    expect(() => randomBytes(0)).toThrow(TypeError);
    expect(() => randomBytes(-1)).toThrow(TypeError);
  });

  it('round-trips base64url', () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255]);
    expect(Array.from(base64urlDecode(base64urlEncode(bytes)))).toEqual(Array.from(bytes));
    expect(base64urlEncode(new TextEncoder().encode('とむ'))).not.toContain('=');
    expect(base64urlDecodeToString(base64urlEncode(new TextEncoder().encode('とむ')))).toBe('とむ');
  });

  it('matches the SHA-256 test vector', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('compares equal-length strings in constant time', () => {
    expect(timingSafeEqual('a'.repeat(64), 'a'.repeat(64))).toBe(true);
    expect(timingSafeEqual('a'.repeat(64), 'a'.repeat(63) + 'b')).toBe(false);
    expect(timingSafeEqual('short', 'longer')).toBe(false);
  });

  it('compares arbitrary-length secrets without leaking length', async () => {
    expect(await secretEquals('token', 'token')).toBe(true);
    expect(await secretEquals('token', 'token-but-much-longer')).toBe(false);
    expect(await secretEquals('', '')).toBe(true);
  });

  it('verifies a raw secret against its stored hash', async () => {
    const secret = randomToken();
    const stored = await sha256Hex(secret);
    expect(await verifySecretHash(secret, stored)).toBe(true);
    expect(await verifySecretHash(`${secret}x`, stored)).toBe(false);
  });

  it('fingerprints without exposing the secret', async () => {
    const secret = randomToken();
    const fp = await fingerprint(secret);
    expect(fp).toHaveLength(12);
    expect(secret).not.toContain(fp);
    expect(await fingerprint(secret)).toBe(fp);
  });
});
