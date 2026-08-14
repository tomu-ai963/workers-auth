import { describe, expect, it } from 'vitest';

import {
  getCookie,
  parseCookies,
  resolveCookieConfig,
  serializeCookie,
  serializeCookieDeletion,
} from '../src/cookie.js';

describe('cookie defaults', () => {
  it('defaults to __Host- prefixed, secure names', () => {
    const config = resolveCookieConfig();
    expect(config.sessionCookieName).toBe('__Host-session');
    expect(config.csrfCookieName).toBe('__Host-csrf');
    expect(config.secure).toBe(true);
    expect(config.sameSite).toBe('Lax');
    expect(config.path).toBe('/');
  });

  it('honours custom base names but keeps the prefix', () => {
    const config = resolveCookieConfig({ name: 'sid', csrfName: 'xsrf' });
    expect(config.sessionCookieName).toBe('__Host-sid');
    expect(config.csrfCookieName).toBe('__Host-xsrf');
  });

  it('refuses to drop the prefix without the danger flag', () => {
    expect(() => resolveCookieConfig({ prefix: '' })).toThrow(/dangerouslyAllowInsecureCookies/);
  });

  it('refuses a prefix without Secure', () => {
    expect(() =>
      resolveCookieConfig({ prefix: '__Host-', dangerouslyAllowInsecureCookies: true }),
    ).toThrow(/requires Secure/);
  });

  it('allows insecure cookies only via the explicit escape hatch', () => {
    const config = resolveCookieConfig({ dangerouslyAllowInsecureCookies: true });
    expect(config.sessionCookieName).toBe('session');
    expect(config.secure).toBe(false);
  });

  it('rejects colliding names and invalid tokens', () => {
    expect(() => resolveCookieConfig({ name: 'a', csrfName: 'a' })).toThrow(/must differ/);
    expect(() => resolveCookieConfig({ name: 'bad name' })).toThrow(/cookie tokens/);
  });
});

describe('cookie serialization', () => {
  it('emits the full secure attribute set', () => {
    const header = serializeCookie('__Host-session', 'abc', { maxAge: 3600 });
    expect(header).toContain('__Host-session=abc');
    expect(header).toContain('Path=/');
    expect(header).toContain('HttpOnly');
    expect(header).toContain('Secure');
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Max-Age=3600');
  });

  it('rejects __Host- cookies that browsers would drop', () => {
    expect(() => serializeCookie('__Host-session', 'a', { domain: 'example.com' })).toThrow();
    expect(() => serializeCookie('__Host-session', 'a', { path: '/api' })).toThrow();
    expect(() => serializeCookie('__Host-session', 'a', { secure: false })).toThrow();
    expect(() => serializeCookie('__Secure-session', 'a', { secure: false })).toThrow();
  });

  it('can opt out of HttpOnly for the readable CSRF cookie', () => {
    const header = serializeCookie('__Host-csrf', 'tok', { httpOnly: false });
    expect(header).not.toContain('HttpOnly');
    expect(header).toContain('Secure');
  });

  it('encodes values so they cannot break the header', () => {
    const header = serializeCookie('__Host-session', 'a;b c');
    expect(header.startsWith('__Host-session=a%3Bb%20c;')).toBe(true);
  });

  it('deletes with Max-Age=0', () => {
    expect(serializeCookieDeletion('__Host-session')).toContain('Max-Age=0');
  });

  it('parses cookie headers and ignores shadowing duplicates', () => {
    const jar = parseCookies('__Host-session=abc; __Host-csrf=xyz; __Host-session=evil');
    expect(jar['__Host-session']).toBe('abc');
    expect(jar['__Host-csrf']).toBe('xyz');
    expect(parseCookies(null)).toEqual({});
  });

  it('reads a cookie off a Request', () => {
    const req = new Request('https://example.com/', { headers: { cookie: '__Host-session=abc' } });
    expect(getCookie(req, '__Host-session')).toBe('abc');
    expect(getCookie(req, 'nope')).toBeUndefined();
  });
});
