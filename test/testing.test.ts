import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  cookieHeader,
  extractMagicLinkFromEmail,
  getSetCookies,
  loginForCookies,
  readCookieJar,
  waitForEmail,
} from '../src/testing.js';
import type { EmailLike } from '../src/testing.js';

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

/**
 * A plausible transactional email: a logo, the magic link itself, and the
 * footer links every real template carries. The point of the fixture is that
 * the link under test is *not* the first URL in the body.
 */
const HTML_EMAIL = `
  <html><body>
    <img src="https://cdn.example.com/logo.png" alt="Example">
    <p>Hi — click below to sign in.</p>
    <a href="https://app.example.com/auth/callback?token=abc123&amp;email=user%40example.com">Sign in</a>
    <p><a href="https://example.com/help">Help</a> · <a href="https://example.com/unsubscribe">Unsubscribe</a></p>
  </body></html>
`;

describe('extractMagicLinkFromEmail', () => {
  it('pulls the link out of an HTML body', () => {
    expect(extractMagicLinkFromEmail(HTML_EMAIL)).toBe(
      'https://app.example.com/auth/callback?token=abc123&email=user%40example.com',
    );
  });

  it('decodes &amp; so every parameter after the first survives', () => {
    const url = new URL(extractMagicLinkFromEmail(HTML_EMAIL));
    expect(url.searchParams.get('token')).toBe('abc123');
    expect(url.searchParams.get('email')).toBe('user@example.com');
  });

  it('prefers a URL with a token-ish query parameter over earlier URLs', () => {
    const body = [
      'https://example.com/home',
      'https://cdn.example.com/pixel.gif?utm_source=email',
      'https://app.example.com/callback?magic_token=xyz789',
      'https://example.com/unsubscribe',
    ].join('\n');
    expect(extractMagicLinkFromEmail(body)).toBe('https://app.example.com/callback?magic_token=xyz789');
  });

  it('recognises token-ish keys whatever the casing or separator', () => {
    for (const key of ['token', 'magic_token', 'magicToken', 'verify-token', 'magiclink']) {
      const body = `https://example.com/home\nhttps://app.example.com/go?${key}=v`;
      expect(extractMagicLinkFromEmail(body)).toBe(`https://app.example.com/go?${key}=v`);
    }
  });

  it('falls back to an auth-looking path when no query key is token-ish', () => {
    const body = 'https://example.com/pricing\nhttps://app.example.com/verify/abc123\nhttps://example.com/blog';
    expect(extractMagicLinkFromEmail(body)).toBe('https://app.example.com/verify/abc123');
  });

  it('falls back to the first URL when nothing stands out', () => {
    const body = 'https://example.com/a and https://example.com/b';
    expect(extractMagicLinkFromEmail(body)).toBe('https://example.com/a');
  });

  it('strips sentence punctuation that the URL pattern would otherwise swallow', () => {
    const body = 'Sign in at https://app.example.com/callback?token=abc123.';
    expect(extractMagicLinkFromEmail(body)).toBe('https://app.example.com/callback?token=abc123');
  });

  it('throws with the body length when no URL is present', () => {
    const body = 'Your sign-in code is 123456.';
    expect(() => extractMagicLinkFromEmail(body)).toThrow(
      `extractMagicLinkFromEmail: no URL matched in body (length: ${body.length})`,
    );
  });

  it('throws on an empty body', () => {
    expect(() => extractMagicLinkFromEmail('')).toThrow(/no URL matched in body \(length: 0\)/);
  });

  describe('options.pattern', () => {
    it('replaces the default scan entirely — including for non-http schemes', () => {
      const body = 'Open https://example.com/help or exampleapp://login?token=deep123 in the app.';
      expect(extractMagicLinkFromEmail(body, { pattern: /exampleapp:\/\/[^\s]+/ })).toBe(
        'exampleapp://login?token=deep123',
      );
    });

    it('returns capture group 1 when the pattern has one', () => {
      const body = '<a data-magic="https://app.example.com/go?token=cap1">Sign in</a>';
      expect(extractMagicLinkFromEmail(body, { pattern: /data-magic="([^"]+)"/ })).toBe(
        'https://app.example.com/go?token=cap1',
      );
    });

    it('honours a capture group even on a /g pattern', () => {
      const body = 'link: [https://app.example.com/go?token=g1] [https://example.com/other]';
      expect(extractMagicLinkFromEmail(body, { pattern: /\[(https:\/\/app[^\]]+)\]/g })).toBe(
        'https://app.example.com/go?token=g1',
      );
    });

    it('throws naming the pattern when it does not match', () => {
      expect(() => extractMagicLinkFromEmail(HTML_EMAIL, { pattern: /nope:\/\/\S+/ })).toThrow(
        /options\.pattern .*nope.* did not match in body \(length: \d+\)/,
      );
    });
  });
});

const SIGN_IN_EMAIL: EmailLike = {
  to: 'user@example.com',
  subject: 'Sign in to Example',
  html: '<a href="https://app.example.com/callback?token=abc123">Sign in</a>',
  createdAt: '2026-01-01T00:00:00.000Z',
};

const NOISE_EMAIL: EmailLike = { to: 'user@example.com', subject: 'Weekly digest' };

/**
 * Hands back one batch per call, repeating the last batch once the script runs
 * out — a real inbox keeps returning what is in it, it does not empty itself.
 * Written by hand rather than with `vi.fn()` so the assertions read as "what
 * the caller's fetcher was asked for", independent of mock plumbing.
 */
function scriptedInbox(batches: EmailLike[][]) {
  let calls = 0;
  return {
    fetchEmails: async (): Promise<EmailLike[]> => {
      const batch = batches[Math.min(calls, batches.length - 1)] ?? [];
      calls += 1;
      return batch;
    },
    get calls() {
      return calls;
    },
  };
}

describe('waitForEmail', () => {
  // Fake timers throughout: the default timeout is 10s, and a suite that spends
  // that in real time is a suite people stop running.
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns a match found on the first poll without waiting an interval', async () => {
    const inbox = scriptedInbox([[SIGN_IN_EMAIL]]);
    await expect(
      waitForEmail(inbox.fetchEmails, (email) => email.subject === 'Sign in to Example'),
    ).resolves.toBe(SIGN_IN_EMAIL);
    expect(inbox.calls).toBe(1);
  });

  it('polls again after intervalMs when the first fetch is empty', async () => {
    const inbox = scriptedInbox([[], [NOISE_EMAIL, SIGN_IN_EMAIL]]);
    const pending = waitForEmail(inbox.fetchEmails, (email) => email.subject === 'Sign in to Example');

    await vi.advanceTimersByTimeAsync(500);

    await expect(pending).resolves.toBe(SIGN_IN_EMAIL);
    expect(inbox.calls).toBe(2);
  });

  it('honours a custom intervalMs', async () => {
    const inbox = scriptedInbox([[], [SIGN_IN_EMAIL]]);
    const pending = waitForEmail(inbox.fetchEmails, () => true, { intervalMs: 50 });

    await vi.advanceTimersByTimeAsync(50);

    await expect(pending).resolves.toBe(SIGN_IN_EMAIL);
    expect(inbox.calls).toBe(2);
  });

  it('rejects once timeoutMs elapses, reporting polls and the last fetch size', async () => {
    const inbox = scriptedInbox([[NOISE_EMAIL]]);
    const pending = waitForEmail(inbox.fetchEmails, (email) => email.subject === 'Sign in to Example', {
      timeoutMs: 2000,
      intervalMs: 500,
    });
    // Attach the rejection handler before advancing, or the rejection surfaces
    // as an unhandled one first.
    const rejects = expect(pending).rejects.toThrow(
      'waitForEmail: no email matched after 5 poll(s) over 2000ms (last fetch returned 1 email(s))',
    );

    await vi.advanceTimersByTimeAsync(2000);

    await rejects;
    // Polls land at 0, 500, 1000, 1500 and 2000ms — the last one on the deadline.
    expect(inbox.calls).toBe(5);
  });

  it('reports a last fetch of 0 when nothing was ever delivered', async () => {
    const inbox = scriptedInbox([[]]);
    const pending = waitForEmail(inbox.fetchEmails, () => true, { timeoutMs: 1000, intervalMs: 1000 });
    const rejects = expect(pending).rejects.toThrow(/last fetch returned 0 email\(s\)/);

    await vi.advanceTimersByTimeAsync(1000);

    await rejects;
  });

  it('polls exactly once when timeoutMs is 0', async () => {
    const inbox = scriptedInbox([[]]);
    await expect(waitForEmail(inbox.fetchEmails, () => true, { timeoutMs: 0 })).rejects.toThrow(
      /after 1 poll\(s\) over 0ms/,
    );
    expect(inbox.calls).toBe(1);
  });

  it('never sleeps past the deadline when intervalMs exceeds what is left', async () => {
    const inbox = scriptedInbox([[]]);
    const pending = waitForEmail(inbox.fetchEmails, () => true, { timeoutMs: 600, intervalMs: 500 });
    const rejects = expect(pending).rejects.toThrow(/after 3 poll\(s\) over 600ms/);

    // Polls at 0 and 500; the third sleep is clamped to the remaining 100ms
    // rather than overshooting to 1000.
    await vi.advanceTimersByTimeAsync(600);

    await rejects;
    expect(inbox.calls).toBe(3);
  });

  it('surfaces an error thrown by fetchEmails instead of retrying past it', async () => {
    const boom = async (): Promise<EmailLike[]> => {
      throw new Error('inbox API 503');
    };
    await expect(waitForEmail(boom, () => true)).rejects.toThrow('inbox API 503');
  });
});
