import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createGoogleOAuthClient, createGoogleOAuthFlow, GMAIL_READONLY_SCOPE, GOOGLE_OAUTH_REDIRECT_URI, TRUSTVAULT_FRONTEND_ORIGIN } from '../googleOAuth.js';

test('Google OAuth flow state is unpredictable, short-lived, bound to a session, and one-use', () => {
  let now = 1000;
  const flow = createGoogleOAuthFlow({ now: () => now, ttlMs: 600, maxPending: 2 });
  const first = flow.begin('authenticated-session-a');
  const second = flow.begin('authenticated-session-b');

  assert.match(first.state, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.state, second.state);
  assert.notEqual(first.flowCookie, second.flowCookie);
  assert.equal(flow.consume(first.state, 'wrong-flow-cookie-value-0000000000000000000000'), null);
  assert.deepEqual(flow.consume(first.state, first.flowCookie), { sessionId: 'authenticated-session-a' });
  assert.equal(flow.consume(first.state, first.flowCookie), null);
  assert.deepEqual(flow.consume(second.state, second.flowCookie), { sessionId: 'authenticated-session-b' });

  const expired = flow.begin('authenticated-session-c');
  now += 600;
  assert.equal(flow.consume(expired.state, expired.flowCookie), null);
  assert.equal(flow.pendingCount, 0);
});

test('Google OAuth constants pin read-only scope and the requested local callback/origin', () => {
  assert.equal(GMAIL_READONLY_SCOPE, 'https://www.googleapis.com/auth/gmail.readonly');
  assert.equal(GOOGLE_OAUTH_REDIRECT_URI, 'http://localhost:4000/api/auth/google/callback');
  assert.equal(TRUSTVAULT_FRONTEND_ORIGIN, 'http://localhost:5173');
});

test('official googleapis OAuth client builds a backend authorization-code URL without network access', () => {
  const client = createGoogleOAuthClient({
    clientId: 'fictional-client.apps.googleusercontent.com',
    clientSecret: 'fictional-client-secret',
    redirectUri: GOOGLE_OAUTH_REDIRECT_URI,
  });
  const authorizationUrl = new URL(client.generateAuthUrl({
    access_type: 'online',
    include_granted_scopes: false,
    scope: [GMAIL_READONLY_SCOPE],
    state: 'A'.repeat(43),
  }));
  assert.equal(authorizationUrl.origin, 'https://accounts.google.com');
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('redirect_uri'), GOOGLE_OAUTH_REDIRECT_URI);
  assert.equal(authorizationUrl.searchParams.get('scope'), GMAIL_READONLY_SCOPE);
  assert.equal(authorizationUrl.searchParams.has('client_secret'), false);
  assert.equal(authorizationUrl.searchParams.get('access_type'), 'online');
});
