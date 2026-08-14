import { describe, expect, it } from 'vitest';

import { checkDoubleSubmit, checkOrigin, isStateChanging, issueCsrfToken, verifyCsrf } from '../src/csrf.js';

function post(headers: Record<string, string> = {}): Request {
  return new Request('https://app.example.com/api/thing', { method: 'POST', headers });
}

describe('csrf', () => {
  it('classifies methods', () => {
    expect(isStateChanging('GET')).toBe(false);
    expect(isStateChanging('head')).toBe(false);
    expect(isStateChanging('OPTIONS')).toBe(false);
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(isStateChanging(method)).toBe(true);
    }
  });

  it('requires a matching Origin header', () => {
    expect(checkOrigin(post())).toEqual({ ok: false, reason: 'origin_missing' });
    expect(checkOrigin(post({ origin: 'null' }))).toEqual({ ok: false, reason: 'origin_missing' });
    expect(checkOrigin(post({ origin: 'https://evil.example.com' }))).toEqual({
      ok: false,
      reason: 'origin_mismatch',
    });
    expect(checkOrigin(post({ origin: 'not a url' }))).toEqual({ ok: false, reason: 'origin_mismatch' });
    expect(checkOrigin(post({ origin: 'https://app.example.com' }))).toEqual({ ok: true });
  });

  it('accepts explicitly trusted origins only', () => {
    const req = post({ origin: 'https://admin.example.com' });
    expect(checkOrigin(req, ['https://admin.example.com'])).toEqual({ ok: true });
    expect(checkOrigin(req, ['https://other.example.com'])).toEqual({
      ok: false,
      reason: 'origin_mismatch',
    });
  });

  it('does not treat a subdomain as the same origin', () => {
    expect(checkOrigin(post({ origin: 'https://evil.app.example.com' }))).toEqual({
      ok: false,
      reason: 'origin_mismatch',
    });
  });

  it('compares the double-submit token', async () => {
    const token = issueCsrfToken();
    expect(await checkDoubleSubmit(post({ 'x-csrf-token': token }), token)).toEqual({ ok: true });
    expect(await checkDoubleSubmit(post({ 'x-csrf-token': token }), 'other')).toEqual({
      ok: false,
      reason: 'token_mismatch',
    });
    expect(await checkDoubleSubmit(post(), token)).toEqual({ ok: false, reason: 'token_missing' });
    expect(await checkDoubleSubmit(post({ 'x-csrf-token': token }), undefined)).toEqual({
      ok: false,
      reason: 'token_missing',
    });
  });

  it('lets safe methods through untouched', async () => {
    const req = new Request('https://app.example.com/api/thing');
    expect(await verifyCsrf({ req, cookieToken: undefined, cookieAuthenticated: true })).toEqual({ ok: true });
  });

  it('rejects a cookie-authenticated POST without a token', async () => {
    const req = post({ origin: 'https://app.example.com' });
    expect(await verifyCsrf({ req, cookieToken: undefined, cookieAuthenticated: true })).toEqual({
      ok: false,
      reason: 'token_missing',
    });
  });

  it('rejects a cookie-authenticated POST from another origin', async () => {
    const token = issueCsrfToken();
    const req = post({ origin: 'https://evil.example.com', 'x-csrf-token': token });
    expect(await verifyCsrf({ req, cookieToken: token, cookieAuthenticated: true })).toEqual({
      ok: false,
      reason: 'origin_mismatch',
    });
  });

  it('accepts a well-formed cookie-authenticated POST', async () => {
    const token = issueCsrfToken();
    const req = post({ origin: 'https://app.example.com', 'x-csrf-token': token });
    expect(await verifyCsrf({ req, cookieToken: token, cookieAuthenticated: true })).toEqual({ ok: true });
  });

  it('demands an Origin on the session endpoints even with no cookies', async () => {
    expect(
      await verifyCsrf({ req: post(), cookieToken: undefined, cookieAuthenticated: false, requireOrigin: true }),
    ).toEqual({ ok: false, reason: 'origin_missing' });

    expect(
      await verifyCsrf({
        req: post({ origin: 'https://app.example.com' }),
        cookieToken: undefined,
        cookieAuthenticated: false,
        requireOrigin: true,
      }),
    ).toEqual({ ok: true });

    expect(
      await verifyCsrf({
        req: post({ origin: 'https://evil.example.com' }),
        cookieToken: undefined,
        cookieAuthenticated: false,
        requireOrigin: true,
      }),
    ).toEqual({ ok: false, reason: 'origin_mismatch' });
  });

  it('skips the check for bearer-only requests', async () => {
    const req = post({ authorization: 'Bearer whatever' });
    expect(await verifyCsrf({ req, cookieToken: undefined, cookieAuthenticated: false })).toEqual({ ok: true });
  });

  it('still checks when a CSRF cookie is present without a session', async () => {
    const token = issueCsrfToken();
    const req = post({ origin: 'https://evil.example.com', 'x-csrf-token': token });
    expect(await verifyCsrf({ req, cookieToken: token, cookieAuthenticated: false })).toEqual({
      ok: false,
      reason: 'origin_mismatch',
    });
  });
});
