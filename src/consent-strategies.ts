import type { OAuthAuthorizationRequest } from './oauth.js';

export interface CookieConsentOptions {
  /** Base URL of the app whose identity provider fronts the MCP server. */
  appBaseUrl: string;
  email: string;
  password: string;
  /** Better Auth email sign-in path (default `/api/auth/sign-in/email`). */
  signInPath?: string;
}

/**
 * Headless consent for MCP servers fronted by a Better Auth email/password
 * login: sign in for a session cookie, drive the OAuth `authorize` endpoint with
 * it, and read the authorization code from the redirect — no browser, no
 * callback server. Suitable for CI and fully-autonomous agents against an
 * instance whose identity provider you control.
 */
export function cookieConsentStrategy(options: CookieConsentOptions) {
  const signInPath = options.signInPath ?? '/api/auth/sign-in/email';
  return async ({ authorizationUrl }: OAuthAuthorizationRequest): Promise<{ code: string }> => {
    const origin = new URL(options.appBaseUrl).origin;
    const signIn = await fetch(new URL(signInPath, options.appBaseUrl), {
      method: 'POST',
      // Better Auth rejects state-changing requests without an Origin in trustedOrigins.
      headers: { 'content-type': 'application/json', origin },
      body: JSON.stringify({ email: options.email, password: options.password }),
      redirect: 'manual',
    });
    const cookie = (signIn.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).join('; ');
    if (!cookie) {
      throw new Error(`cookieConsent: sign-in set no cookie (status ${signIn.status})`);
    }
    const authorize = await fetch(authorizationUrl, { headers: { cookie }, redirect: 'manual' });
    const location = authorize.headers.get('location');
    if (!location) {
      throw new Error(
        `cookieConsent: authorize did not redirect (status ${authorize.status}); an interactive consent UI may be required`
      );
    }
    const code = new URL(location).searchParams.get('code');
    if (!code) {
      throw new Error(`cookieConsent: no authorization code in redirect: ${location}`);
    }
    return { code };
  };
}
