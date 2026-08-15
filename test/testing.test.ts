import { describe, expect, it } from 'vitest';

import { cookieHeader, getSetCookies, loginForCookies, readCookieJar } from '../src/testing.js';

/**
 * A minimal stand-in for a real `Response`'s `Set-Cookie` handling. Node's
 * `Headers` (and workerd's) both expose `getSetCookie()`, but it's easiest to
 * assert against a fixed list of raw header lines here.
 */
function responseWithSetCookies(headers: string[], status = 200): Response {
  const res = new Response(null, { status });
  for (const header of headers) {
    res.headers.append('set-cookie', header);
  }
  return res;
}

describe('getSetCookies', () => {
  it('returns every Set-Cookie header, not just the first', () => {
    const res = responseWithSetCookies(['a=1; Path=/', 'b=2; Path=/; HttpOnly']);
    expect(getSetCookies(res)).toEqual(['a=1; Path=/', 'b=2; Path=/; HttpOnly']);
  });

  it('returns an empty array when there are none', () => {
    expect(getSetCookies(new Response())).toEqual([]);
  });
});

describe('readCookieJar', () => {
  it('parses name/value pairs, discarding attributes', () => {
    const res = responseWithSetCookies([
      '__Host-session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax',
      '__Host-csrf=def456; Path=/; Secure; SameSite=Lax',
    ]);
    expect(readCookieJar(res)).toEqual({ '__Host-session': 'abc123', '__Host-csrf': 'def456' });
  });

  it('does not assume any particular cookie name or prefix', () => {
    const res = responseWithSetCookies(['session=xyz; Path=/', 'my_custom_csrf=qqq; Path=/']);
    expect(readCookieJar(res)).toEqual({ session: 'xyz', my_custom_csrf: 'qqq' });
  });

  it('URL-decodes values', () => {
    const res = responseWithSetCookies([`token=${encodeURIComponent('a b/c')}; Path=/`]);
    expect(readCookieJar(res).token).toBe('a b/c');
  });

  it('captures a deletion (empty value) as an empty string rather than dropping it', () => {
    const res = responseWithSetCookies(['session=; Path=/; Max-Age=0']);
    expect(readCookieJar(res)).toEqual({ session: '' });
  });

  it('returns an empty jar for a response with no cookies', () => {
    expect(readCookieJar(new Response())).toEqual({});
  });
});

describe('cookieHeader', () => {
  it('joins entries as name=value pairs separated by "; "', () => {
    expect(cookieHeader({ a: '1', b: '2' })).toBe('a=1; b=2');
  });

  it('encodes values', () => {
    expect(cookieHeader({ token: 'a b/c' })).toBe(`token=${encodeURIComponent('a b/c')}`);
  });

  it('drops entries with an empty value — a parsed deletion should not be replayed', () => {
    expect(cookieHeader({ session: 'abc', csrf: '' })).toBe('session=abc');
  });

  it('round-trips what readCookieJar produced', () => {
    const res = responseWithSetCookies(['__Host-session=abc123; Path=/', '__Host-csrf=def456; Path=/']);
    const jar = readCookieJar(res);
    expect(cookieHeader(jar)).toBe('__Host-session=abc123; __Host-csrf=def456');
  });
});

describe('loginForCookies', () => {
  it('returns the jar on a 200 response', async () => {
    const fetcher = () => responseWithSetCookies(['session=abc; Path=/']);
    const jar = await loginForCookies(fetcher, new Request('https://example.com/auth/session'));
    expect(jar).toEqual({ session: 'abc' });
  });

  it('passes the request through to the fetcher unmodified', async () => {
    let received: Request | undefined;
    const fetcher = (req: Request) => {
      received = req;
      return responseWithSetCookies([]);
    };
    const sent = new Request('https://example.com/auth/session', {
      method: 'POST',
      headers: { authorization: 'Bearer tk_test_x.y' },
    });
    await loginForCookies(fetcher, sent);
    expect(received).toBe(sent);
  });

  it('throws with the status and body on a non-200 response', async () => {
    const fetcher = () =>
      new Response(JSON.stringify({ error: 'unauthenticated' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    await expect(
      loginForCookies(fetcher, new Request('https://example.com/auth/session', { method: 'POST' })),
    ).rejects.toThrow(/expected 200.*got 401.*unauthenticated/s);
  });

  it('supports an async fetcher', async () => {
    const fetcher = async (req: Request) => {
      await Promise.resolve();
      return responseWithSetCookies(['session=abc; Path=/']);
    };
    const jar = await loginForCookies(fetcher, new Request('https://example.com/auth/session'));
    expect(jar).toEqual({ session: 'abc' });
  });
});
