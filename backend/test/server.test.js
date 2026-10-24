import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createApp } from '../server.js';
import { createMessageStore } from '../messageStore.js';
import { hashPassword } from '../passwordAuth.js';
import { createGoogleTokenStore } from '../googleTokenStore.js';
import { GMAIL_READONLY_SCOPE } from '../googleOAuth.js';

const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
const demoMessages = JSON.parse(await readFile(path.join(projectRoot, 'backend/data/messages.json'), 'utf8'))
  .filter((message) => message.id.startsWith('demo-'));
const fixtureCsv = await readFile(path.join(projectRoot, 'examples/fictional-messages.csv'), 'utf8');
const testConfig = {
  sessionSecret: Buffer.alloc(32, 7),
  tokenEncryptionKey: Buffer.alloc(32, 6),
  messageEncryptionKey: Buffer.alloc(32, 8),
  authPasswordHash: await hashPassword('TrustVault-Test-Password-123'),
};

async function createTestServer(t, store, config = testConfig) {
  const server = createApp(store, config).listen(0, '127.0.0.1');
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  await new Promise((resolve) => server.once('listening', resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

async function newAnonymousSession(baseUrl) {
  const response = await fetch(`${baseUrl}/api/auth/session`);
  const data = await response.json();
  return { cookie: response.headers.get('set-cookie').split(';')[0], csrfToken: data.csrfToken };
}

async function login(baseUrl, session, password = 'TrustVault-Test-Password-123') {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: session.cookie, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  return { response, body: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
}

test('HTTP import endpoint reports imports, duplicates, invalid rows, and malformed files accurately', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-api-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createMessageStore(path.join(directory, 'messages.json'));
  await store.write(demoMessages);
  const { baseUrl } = await createTestServer(t, store);
  const anonymous = await newAnonymousSession(baseUrl);
  const authenticated = await login(baseUrl, anonymous);
  assert.equal(authenticated.response.status, 200);

  async function importCsv(csv) {
    const response = await fetch(`${baseUrl}/api/messages/import`, {
      method: 'POST',
      headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken, 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'fictional.csv', csv }),
    });
    return { status: response.status, body: await response.json() };
  }

  const health = await fetch(`${baseUrl}/api/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, 'ok');
  const frontendOrigin = await fetch(`${baseUrl}/api/health`, { headers: { Origin: 'http://localhost:5173' } });
  assert.equal(frontendOrigin.headers.get('access-control-allow-origin'), 'http://localhost:5173');
  const unrelatedOrigin = await fetch(`${baseUrl}/api/health`, { headers: { Origin: 'https://unrelated.example' } });
  assert.equal(unrelatedOrigin.headers.get('access-control-allow-origin'), null);

  const first = await importCsv(fixtureCsv);
  assert.equal(first.status, 200);
  assert.deepEqual([first.body.imported, first.body.duplicates, first.body.rejected], [2, 0, 0]);
  assert.equal((await store.read()).length, 5);
  const messagesResponse = await fetch(`${baseUrl}/api/messages`, { headers: { Cookie: authenticated.cookie } });
  assert.equal(messagesResponse.headers.get('cache-control'), 'no-store');
  const reportResponse = await fetch(`${baseUrl}/api/messages/${encodeURIComponent(demoMessages[0].id)}/report`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(reportResponse.status, 200);
  assert.equal(reportResponse.headers.get('cache-control'), 'no-store');

  const repeated = await importCsv(fixtureCsv);
  assert.equal(repeated.status, 200);
  assert.deepEqual([repeated.body.imported, repeated.body.duplicates, repeated.body.rejected], [0, 2, 0]);
  assert.equal((await store.read()).length, 5);

  const invalid = await importCsv('sender,subject,body,timestamp,source\nInvalid,,Body,not-a-date,Fictional sample');
  assert.equal(invalid.status, 200);
  assert.deepEqual([invalid.body.imported, invalid.body.duplicates, invalid.body.rejected], [0, 0, 1]);
  assert.equal((await store.read()).length, 5);

  const empty = await importCsv('');
  assert.equal(empty.status, 400);
  assert.match(empty.body.errors.join(' '), /empty/);

  const malformed = await importCsv('sender,subject,body,timestamp,source\nCafe,,"unfinished,2026-10-20T10:00:00Z,Sample');
  assert.equal(malformed.status, 400);
  assert.match(malformed.body.errors.join(' '), /not closed/);
  assert.equal((await store.read()).length, 5);
});

test('malformed JSON requests return a clear client error instead of a server error', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-api-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')));
  const response = await fetch(`${baseUrl}/api/messages/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{bad json',
  });
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /valid JSON/);
});

test('login rotates the anonymous session, protects messages, and logout revokes it', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-auth-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createMessageStore(path.join(directory, 'messages.json'));
  await store.write(demoMessages);
  const { baseUrl } = await createTestServer(t, store);

  const unauthorizedMessages = await fetch(`${baseUrl}/api/messages`);
  assert.equal(unauthorizedMessages.status, 401);
  assert.equal(unauthorizedMessages.headers.get('cache-control'), 'no-store');
  const anonymous = await newAnonymousSession(baseUrl);
  const anonymousImport = await fetch(`${baseUrl}/api/messages/import`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename: 'empty.csv', csv: '' }),
  });
  assert.equal(anonymousImport.status, 401);
  const anonymousReport = await fetch(`${baseUrl}/api/messages/demo-1/report`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken },
  });
  assert.equal(anonymousReport.status, 401);
  const wrongPassword = await login(baseUrl, anonymous, 'incorrect password value');
  assert.equal(wrongPassword.response.status, 401);

  const authenticated = await login(baseUrl, anonymous);
  assert.equal(authenticated.response.status, 200);
  assert.notEqual(authenticated.cookie, anonymous.cookie);
  assert.match(authenticated.response.headers.get('set-cookie'), /HttpOnly/);
  assert.match(authenticated.response.headers.get('set-cookie'), /SameSite=Strict/);
  assert.doesNotMatch(authenticated.response.headers.get('set-cookie'), /Domain=/);
  assert.equal((await fetch(`${baseUrl}/api/messages`, { headers: { Cookie: authenticated.cookie } })).status, 200);

  const logout = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(logout.status, 200);
  assert.equal((await logout.json()).authenticated, false);
  assert.equal((await fetch(`${baseUrl}/api/messages`, { headers: { Cookie: authenticated.cookie } })).status, 401);
});

test('HTTP login throttles repeated failures before another password check', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-login-limit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = { ...testConfig, loginRateLimitOptions: { maxFailures: 2, windowMs: 60_000, lockoutMs: 60_000 } };
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')), config);
  const anonymous = await newAnonymousSession(baseUrl);
  const attempts = [];
  for (let index = 0; index < 3; index += 1) {
    attempts.push(await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken, 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'wrong-password-for-test' }),
    }));
  }
  assert.deepEqual(attempts.map((response) => response.status), [401, 401, 429]);
  assert.equal(Number(attempts[2].headers.get('retry-after')) > 0, true);
});

test('Google OAuth routes require the local login and report missing configuration safely', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-google-disabled-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')));
  const anonymous = await newAnonymousSession(baseUrl);
  const unauthenticatedStart = await fetch(`${baseUrl}/api/auth/google/start`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken },
  });
  assert.equal(unauthenticatedStart.status, 401);
  assert.equal((await fetch(`${baseUrl}/api/auth/google/status`)).status, 401);

  const authenticated = await login(baseUrl, anonymous);
  const status = await fetch(`${baseUrl}/api/auth/google/status`, { headers: { Cookie: authenticated.cookie } });
  assert.equal(status.status, 200);
  assert.equal(status.headers.get('cache-control'), 'no-store');
  const statusBody = await status.json();
  assert.equal(statusBody.enabled, false);
  assert.equal(statusBody.connected, false);
  assert.match(statusBody.message, /GOOGLE_OAUTH_CLIENT_ID.*GOOGLE_OAUTH_CLIENT_SECRET/);

  const missingConfig = await fetch(`${baseUrl}/api/auth/google/start`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(missingConfig.status, 503);
  const body = await missingConfig.json();
  assert.match(body.error, /GOOGLE_OAUTH_CLIENT_ID/);
  assert.doesNotMatch(JSON.stringify(body), /client-secret|access_token|refresh_token/i);
});

test('Google OAuth persists only verified read-only tokens and supports authenticated local disconnect', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-google-flow-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const generatedOptions = [];
  const exchangedCodes = [];
  let shouldFailExchange = false;
  let responseTokens = {
    access_token: 'never-return-this-access-token',
    refresh_token: 'never-return-this-refresh-token',
    expiry_date: Date.now() + 60_000,
    scope: 'https://www.googleapis.com/auth/gmail.readonly',
  };
  const config = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthRedirectUri: 'http://localhost:4000/api/auth/google/callback',
    googleOAuthEnabled: true,
    googleTokenFilePath: path.join(directory, 'private', 'gmail-tokens.enc'),
    googleOAuthClientFactory: () => ({
      generateAuthUrl(options) {
        generatedOptions.push(options);
        const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        url.searchParams.set('client_id', 'fictional-client-id');
        url.searchParams.set('scope', options.scope.join(' '));
        url.searchParams.set('state', options.state);
        url.searchParams.set('access_type', options.access_type);
        return url.toString();
      },
      async getToken(code) {
        exchangedCodes.push(code);
        if (shouldFailExchange) throw new Error('fictional provider failure');
        return { tokens: responseTokens };
      },
    }),
  };
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')), config);
  const anonymous = await newAnonymousSession(baseUrl);
  const authenticated = await login(baseUrl, anonymous);

  async function startFlow() {
    return fetch(`${baseUrl}/api/auth/google/start`, {
      method: 'POST',
      headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
    });
  }

  const started = await startFlow();
  assert.equal(started.status, 200);
  assert.equal(started.headers.get('cache-control'), 'no-store');
  const startBody = await started.json();
  const authUrl = new URL(startBody.authorizationUrl);
  assert.equal(authUrl.origin, 'https://accounts.google.com');
  assert.equal(authUrl.searchParams.get('scope'), 'https://www.googleapis.com/auth/gmail.readonly');
  assert.equal(authUrl.searchParams.has('client_secret'), false);
  assert.equal(generatedOptions[0].include_granted_scopes, false);
  assert.equal(generatedOptions[0].access_type, 'online');
  assert.deepEqual(generatedOptions[0].scope, ['https://www.googleapis.com/auth/gmail.readonly']);

  const setCookies = started.headers.getSetCookie?.() || [started.headers.get('set-cookie') || ''];
  const flowCookieSet = setCookies.find((cookie) => cookie.startsWith('tv_google_flow='));
  assert.ok(flowCookieSet);
  assert.match(flowCookieSet, /Path=\/api\/auth\/google\/callback/);
  assert.match(flowCookieSet, /HttpOnly/);
  assert.match(flowCookieSet, /SameSite=Lax/);
  const flowCookie = flowCookieSet.split(';')[0];
  const state = authUrl.searchParams.get('state');
  assert.equal(state.length, 43);

  const wrongStateResponse = await fetch(`${baseUrl}/api/auth/google/callback?state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code=fictional-code`, {
    headers: { Cookie: flowCookie }, redirect: 'manual',
  });
  assert.equal(wrongStateResponse.status, 303);
  assert.equal(new URL(wrongStateResponse.headers.get('location')).searchParams.get('gmail'), 'failed');
  assert.deepEqual(exchangedCodes, []);

  const callback = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(state)}&code=fictional-authorization-code`, {
    headers: { Cookie: flowCookie }, redirect: 'manual',
  });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.get('cache-control'), 'no-store');
  assert.equal(new URL(callback.headers.get('location')).origin, 'http://localhost:5173');
  assert.equal(new URL(callback.headers.get('location')).searchParams.get('gmail'), 'authorized');
  assert.deepEqual(exchangedCodes, ['fictional-authorization-code']);
  assert.doesNotMatch(callback.headers.get('location'), /never-return-this|fictional-client-secret|fictional-authorization-code/);
  assert.doesNotMatch(callback.headers.get('location'), /never-return-this/);
  assert.match(callback.headers.getSetCookie().join('; '), /tv_google_flow=.*Max-Age=0/);
  const tokenFile = await readFile(config.googleTokenFilePath, 'utf8');
  assert.doesNotMatch(tokenFile, /never-return-this/);
  const persistedBundle = await createGoogleTokenStore({
    filePath: config.googleTokenFilePath,
    encryptionKey: testConfig.tokenEncryptionKey,
  }).read();
  assert.deepEqual(persistedBundle, {
    version: 1,
    accessToken: responseTokens.access_token,
    refreshToken: responseTokens.refresh_token,
    expiryDate: responseTokens.expiry_date,
    scopes: [GMAIL_READONLY_SCOPE],
  });

  const connectedStatus = await fetch(`${baseUrl}/api/auth/google/status`, { headers: { Cookie: authenticated.cookie } });
  assert.equal(connectedStatus.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await connectedStatus.json(), {
    enabled: true,
    connected: true,
    scope: 'https://www.googleapis.com/auth/gmail.readonly',
    message: 'Gmail authorization tokens are encrypted in the local app store. No messages have been fetched.',
  });

  const anonymousDisconnect = await fetch(`${baseUrl}/api/auth/google/disconnect`, {
    method: 'DELETE', headers: { Origin: 'http://localhost:5173' },
  });
  assert.equal(anonymousDisconnect.status, 401);

  const replay = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(state)}&code=fictional-authorization-code`, {
    headers: { Cookie: flowCookie }, redirect: 'manual',
  });
  assert.equal(new URL(replay.headers.get('location')).searchParams.get('gmail'), 'failed');
  assert.equal(exchangedCodes.length, 1);

  const scopeFlowResponse = await startFlow();
  const scopeUrl = new URL((await scopeFlowResponse.json()).authorizationUrl);
  const scopeCookie = (scopeFlowResponse.headers.getSetCookie() || []).find((cookie) => cookie.startsWith('tv_google_flow=')).split(';')[0];
  responseTokens = { ...responseTokens, scope: 'https://www.googleapis.com/auth/gmail.readonly https://mail.google.com/' };
  const rejectedScope = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(scopeUrl.searchParams.get('state'))}&code=fictional-broad-scope-code`, {
    headers: { Cookie: scopeCookie }, redirect: 'manual',
  });
  assert.equal(new URL(rejectedScope.headers.get('location')).searchParams.get('gmail'), 'failed');
  assert.equal(exchangedCodes.length, 2);
  assert.equal(await readFile(config.googleTokenFilePath, 'utf8'), tokenFile);

  const failureFlowResponse = await startFlow();
  const failureUrl = new URL((await failureFlowResponse.json()).authorizationUrl);
  const failureCookie = (failureFlowResponse.headers.getSetCookie() || []).find((cookie) => cookie.startsWith('tv_google_flow=')).split(';')[0];
  shouldFailExchange = true;
  responseTokens = { ...responseTokens, scope: 'https://www.googleapis.com/auth/gmail.readonly' };
  const providerFailure = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(failureUrl.searchParams.get('state'))}&code=fictional-failure-code`, {
    headers: { Cookie: failureCookie }, redirect: 'manual',
  });
  assert.equal(new URL(providerFailure.headers.get('location')).searchParams.get('gmail'), 'failed');

  const disconnect = await fetch(`${baseUrl}/api/auth/google/disconnect`, {
    method: 'DELETE',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(disconnect.status, 200);
  assert.equal(disconnect.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await disconnect.json(), {
    connected: false,
    removed: true,
    message: 'The encrypted local Gmail token bundle was removed. Google authorization was not revoked.',
  });
  const afterDisconnect = await fetch(`${baseUrl}/api/auth/google/status`, { headers: { Cookie: authenticated.cookie } });
  assert.equal((await afterDisconnect.json()).connected, false);
  const repeatedDisconnect = await fetch(`${baseUrl}/api/auth/google/disconnect`, {
    method: 'DELETE',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal((await repeatedDisconnect.json()).removed, false);

  const expiringFlowResponse = await startFlow();
  const expiringUrl = new URL((await expiringFlowResponse.json()).authorizationUrl);
  const expiringCookie = (expiringFlowResponse.headers.getSetCookie() || []).find((cookie) => cookie.startsWith('tv_google_flow=')).split(';')[0];
  const logout = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(logout.status, 200);
  const exchangesBeforeExpiredSession = exchangedCodes.length;
  const expiredSessionCallback = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(expiringUrl.searchParams.get('state'))}&code=fictional-code-after-logout`, {
    headers: { Cookie: expiringCookie }, redirect: 'manual',
  });
  assert.equal(new URL(expiredSessionCallback.headers.get('location')).searchParams.get('gmail'), 'failed');
  assert.equal(exchangedCodes.length, exchangesBeforeExpiredSession);
});

test('Google callback reports a save failure when encrypted token persistence throws', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-google-save-failure-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let writeAttempts = 0;
  const tokenStore = {
    async write() { writeAttempts += 1; throw new Error('private filesystem details'); },
    async read() { return null; },
    async remove() { return false; },
  };
  const config = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthRedirectUri: 'http://localhost:4000/api/auth/google/callback',
    googleOAuthEnabled: true,
    googleTokenStore: tokenStore,
    googleOAuthClientFactory: () => ({
      generateAuthUrl(options) {
        const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        url.searchParams.set('state', options.state);
        return url.toString();
      },
      async getToken() {
        return { tokens: {
          access_token: 'fictional-access-token',
          refresh_token: 'fictional-refresh-token',
          expiry_date: Date.now() + 60_000,
          scope: GMAIL_READONLY_SCOPE,
        } };
      },
    }),
  };
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')), config);
  const anonymous = await newAnonymousSession(baseUrl);
  const authenticated = await login(baseUrl, anonymous);
  const start = await fetch(`${baseUrl}/api/auth/google/start`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  const authorizationUrl = new URL((await start.json()).authorizationUrl);
  const flowCookie = (start.headers.getSetCookie() || []).find((cookie) => cookie.startsWith('tv_google_flow=')).split(';')[0];
  const callback = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(authorizationUrl.searchParams.get('state'))}&code=fictional-code`, {
    headers: { Cookie: flowCookie },
    redirect: 'manual',
  });

  assert.equal(writeAttempts, 1);
  assert.equal(new URL(callback.headers.get('location')).searchParams.get('gmail'), 'save-failed');
  assert.doesNotMatch(callback.headers.get('location'), /private filesystem details|fictional-access-token|fictional-refresh-token/);
});

test('Google callback reports save failure when write resolves but the encrypted bundle cannot be read back', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-google-readback-failure-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let writes = 0;
  let reads = 0;
  const tokenStore = {
    async write() { writes += 1; },
    async read() { reads += 1; return null; },
    async remove() { return false; },
  };
  const config = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthRedirectUri: 'http://localhost:4000/api/auth/google/callback',
    googleOAuthEnabled: true,
    googleTokenStore: tokenStore,
    googleOAuthClientFactory: () => ({
      generateAuthUrl(options) {
        const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        url.searchParams.set('state', options.state);
        return url.toString();
      },
      async getToken() {
        return { tokens: {
          access_token: 'fictional-access-token',
          refresh_token: null,
          expiry_date: Date.now() + 60_000,
          scope: GMAIL_READONLY_SCOPE,
        } };
      },
    }),
  };
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')), config);
  const anonymous = await newAnonymousSession(baseUrl);
  const authenticated = await login(baseUrl, anonymous);
  const start = await fetch(`${baseUrl}/api/auth/google/start`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  const authorizationUrl = new URL((await start.json()).authorizationUrl);
  const flowCookie = (start.headers.getSetCookie() || []).find((cookie) => cookie.startsWith('tv_google_flow=')).split(';')[0];
  const callback = await fetch(`${baseUrl}/api/auth/google/callback?state=${encodeURIComponent(authorizationUrl.searchParams.get('state'))}&code=fictional-code`, {
    headers: { Cookie: flowCookie },
    redirect: 'manual',
  });

  assert.equal(writes, 1);
  assert.equal(reads, 1);
  assert.equal(new URL(callback.headers.get('location')).searchParams.get('gmail'), 'save-failed');
});

test('missing encrypted token file reports disconnected and sync refuses readiness without Gmail requests', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-google-missing-token-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let gmailRequests = 0;
  const config = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthEnabled: true,
    googleTokenFilePath: path.join(directory, 'private', 'gmail-tokens.enc'),
    gmailApiFactory: () => { gmailRequests += 1; throw new Error('must not be called'); },
  };
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')), config);
  const anonymous = await newAnonymousSession(baseUrl);
  const authenticated = await login(baseUrl, anonymous);

  const status = await fetch(`${baseUrl}/api/auth/google/status`, { headers: { Cookie: authenticated.cookie } });
  assert.equal(status.status, 200);
  assert.equal((await status.json()).connected, false);
  const sync = await fetch(`${baseUrl}/api/auth/google/sync`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(sync.status, 409);
  assert.equal((await sync.json()).reconnectRequired, true);
  assert.equal(gmailRequests, 0);
});

test('state-changing endpoints reject missing CSRF tokens and untrusted origins', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-csrf-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { baseUrl } = await createTestServer(t, createMessageStore(path.join(directory, 'messages.json')));
  const anonymous = await newAnonymousSession(baseUrl);
  const noToken = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'TrustVault-Test-Password-123' }),
  });
  assert.equal(noToken.status, 403);
  assert.equal(noToken.headers.get('cache-control'), 'no-store');
  const wrongOrigin = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { Origin: 'https://untrusted.example', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'TrustVault-Test-Password-123' }),
  });
  assert.equal(wrongOrigin.status, 403);

  const authenticated = await login(baseUrl, anonymous);
  const disconnectWithoutCsrf = await fetch(`${baseUrl}/api/auth/google/disconnect`, {
    method: 'DELETE',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie },
  });
  assert.equal(disconnectWithoutCsrf.status, 403);
  assert.equal(disconnectWithoutCsrf.headers.get('cache-control'), 'no-store');
});

test('Gmail sync is authenticated, CSRF protected, metadata-only, limited to five IDs, and persists rotated tokens', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-gmail-sync-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tokenFilePath = path.join(directory, 'private', 'gmail-tokens.enc');
  const tokenStore = createGoogleTokenStore({ filePath: tokenFilePath, encryptionKey: testConfig.tokenEncryptionKey });
  await tokenStore.write({
    version: 1,
    accessToken: 'fictional-old-access-token',
    refreshToken: 'fictional-old-refresh-token',
    expiryDate: Date.now() + 60_000,
    scopes: [GMAIL_READONLY_SCOPE],
  });
  const apiRequests = [];
  let tokenListener;
  const oauthClientFactory = () => ({
    setCredentials(credentials) {
      assert.equal(credentials.access_token, 'fictional-old-access-token');
      assert.equal(credentials.refresh_token, 'fictional-old-refresh-token');
      assert.equal(credentials.scope, GMAIL_READONLY_SCOPE);
    },
    on(event, listener) { assert.equal(event, 'tokens'); tokenListener = listener; },
  });
  const gmailApiFactory = () => ({ users: { messages: {
    async list(parameters) {
      apiRequests.push({ method: 'list', parameters });
      tokenListener({
        access_token: 'fictional-rotated-access-token',
        refresh_token: 'fictional-rotated-refresh-token',
        expiry_date: Date.now() + 120_000,
        scope: GMAIL_READONLY_SCOPE,
      });
      return { data: { messages: Array.from({ length: 7 }, (_, index) => ({ id: `fictional-message-${index + 1}` })) } };
    },
    async get(parameters) {
      apiRequests.push({ method: 'get', parameters });
      return { data: {
        id: parameters.id,
        snippet: 'must not be returned',
        payload: {
          headers: [
            { name: 'fRoM', value: 'Fictional Sender <sender@example.com>' },
            { name: 'Subject', value: `Fictional subject ${parameters.id}` },
            { name: 'Date', value: 'Thu, 22 Oct 2026 10:00:00 +0000' },
          ],
          body: { data: 'must not be returned' },
          parts: [{ filename: 'must-not-be-requested.txt' }],
        },
      } };
    },
  } } });
  const untouchedMessageStore = {
    read: async () => { throw new Error('Gmail sync must not read the vault store'); },
    write: async () => { throw new Error('Gmail sync must not write the vault store'); },
  };
  const config = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthRedirectUri: 'http://localhost:4000/api/auth/google/callback',
    googleOAuthEnabled: true,
    googleTokenStore: tokenStore,
    googleOAuthClientFactory: oauthClientFactory,
    gmailApiFactory,
    gmailSyncRateLimitOptions: { maxRequests: 1, windowMs: 60_000 },
  };
  const { baseUrl } = await createTestServer(t, untouchedMessageStore, config);
  const anonymous = await newAnonymousSession(baseUrl);
  const unauthenticated = await fetch(`${baseUrl}/api/auth/google/sync`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken },
  });
  assert.equal(unauthenticated.status, 401);
  const authenticated = await login(baseUrl, anonymous);
  const noCsrf = await fetch(`${baseUrl}/api/auth/google/sync`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie },
  });
  assert.equal(noCsrf.status, 403);

  const response = await fetch(`${baseUrl}/api/auth/google/sync`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json();
  assert.equal(body.messages.length, 5);
  assert.deepEqual(Object.keys(body), ['messages']);
  assert.deepEqual(Object.keys(body.messages[0]), ['id', 'sender', 'subject', 'date']);
  assert.equal(body.messages[0].sender, 'Fictional Sender <sender@example.com>');
  assert.equal(JSON.stringify(body).includes('must not be returned'), false);
  assert.doesNotMatch(JSON.stringify(body), /fictional-(old|rotated)-(access|refresh)-token/);
  assert.deepEqual(apiRequests[0], { method: 'list', parameters: { userId: 'me', maxResults: 5, fields: 'messages(id)' } });
  assert.equal(apiRequests.length, 6);
  for (const request of apiRequests.slice(1)) {
    assert.deepEqual(request.parameters, {
      userId: 'me', id: request.parameters.id, format: 'metadata', metadataHeaders: ['From', 'Subject', 'Date'],
      fields: 'id,payload/headers(name,value)',
    });
    assert.equal(Object.hasOwn(request.parameters, 'snippet'), false);
  }
  const savedBundle = await tokenStore.read();
  assert.equal(savedBundle.accessToken, 'fictional-rotated-access-token');
  assert.equal(savedBundle.refreshToken, 'fictional-rotated-refresh-token');

  const limited = await fetch(`${baseUrl}/api/auth/google/sync`, {
    method: 'POST',
    headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
});

test('Gmail sync enforces the stored scope before any API request and handles missing tokens', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-gmail-scope-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let apiCalls = 0;
  const baseConfig = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthRedirectUri: 'http://localhost:4000/api/auth/google/callback',
    googleOAuthEnabled: true,
    gmailApiFactory: () => { apiCalls += 1; return {}; },
    googleOAuthClientFactory: () => ({ setCredentials() {}, on() {} }),
  };
  const broadScopeServer = await createTestServer(t, createMessageStore(path.join(directory, 'broad-messages.json')), {
    ...baseConfig,
    googleTokenStore: { read: async () => ({
      version: 1, accessToken: 'fictional-access-token', refreshToken: null,
      expiryDate: Date.now() + 60_000, scopes: [GMAIL_READONLY_SCOPE, 'https://mail.google.com/'],
    }) },
  });
  const broadSession = await login(broadScopeServer.baseUrl, await newAnonymousSession(broadScopeServer.baseUrl));
  const broadResponse = await fetch(`${broadScopeServer.baseUrl}/api/auth/google/sync`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: broadSession.cookie, 'X-CSRF-Token': broadSession.body.csrfToken },
  });
  assert.equal(broadResponse.status, 403);
  assert.equal(apiCalls, 0);

  const missingServer = await createTestServer(t, createMessageStore(path.join(directory, 'missing-messages.json')), {
    ...baseConfig, googleTokenStore: { read: async () => null },
  });
  const missingSession = await login(missingServer.baseUrl, await newAnonymousSession(missingServer.baseUrl));
  const missingResponse = await fetch(`${missingServer.baseUrl}/api/auth/google/sync`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: missingSession.cookie, 'X-CSRF-Token': missingSession.body.csrfToken },
  });
  assert.equal(missingResponse.status, 409);
  assert.equal(apiCalls, 0);
});

test('Gmail analysis endpoint requires session and CSRF and returns only a temporary selected-message assessment', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-gmail-analysis-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const messageText = 'Your account will be suspended. Reveal your OTP at https://example.com/verify now.';
  const tokenStore = {
    read: async () => ({ version: 1, accessToken: 'fictional-access-token', refreshToken: null, expiryDate: Date.now() + 60_000, scopes: [GMAIL_READONLY_SCOPE] }),
    write: async () => {},
  };
  const apiRequests = [];
  let latestIds = Array.from({ length: 5 }, (_, index) => `selected-${index + 1}`);
  const gmailApiFactory = () => ({ users: { messages: {
    async list(parameters) { apiRequests.push({ method: 'list', parameters }); return { data: { messages: latestIds.map((id) => ({ id })) } }; },
    async get(parameters) {
      apiRequests.push({ method: 'get', parameters });
      if (parameters.format === 'metadata') return { data: { id: parameters.id, payload: { headers: [
        { name: 'From', value: 'Fictional Sender <sender@example.com>' },
        { name: 'Subject', value: 'Fictional security notice' },
        { name: 'Date', value: 'Thu, 22 Oct 2026 10:00:00 +0000' },
      ] } } };
      const payload = { mimeType: 'text/plain', body: parameters.fields.includes('body(data')
        ? { data: Buffer.from(messageText).toString('base64url'), size: Buffer.byteLength(messageText) }
        : { size: Buffer.byteLength(messageText) }, parts: [] };
      return { data: { id: parameters.id, payload, snippet: 'must not be returned', raw: 'must not be returned' } };
    },
  } } });
  const config = {
    ...testConfig,
    googleOAuthClientId: 'fictional-client-id',
    googleOAuthClientSecret: 'fictional-client-secret',
    googleOAuthRedirectUri: 'http://localhost:4000/api/auth/google/callback',
    googleOAuthEnabled: true,
    googleTokenStore: tokenStore,
    googleOAuthClientFactory: () => ({ setCredentials() {}, on() {} }),
    gmailApiFactory,
  };
  const untouchedStore = { read: async () => { throw new Error('Gmail analysis must not read vault data'); }, write: async () => { throw new Error('Gmail analysis must not write vault data'); } };
  const { baseUrl } = await createTestServer(t, untouchedStore, config);
  const anonymous = await newAnonymousSession(baseUrl);
  const unauthorized = await fetch(`${baseUrl}/api/auth/google/analyze`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: anonymous.cookie, 'X-CSRF-Token': anonymous.csrfToken, 'Content-Type': 'application/json' }, body: JSON.stringify({ messageId: 'selected-1' }),
  });
  assert.equal(unauthorized.status, 401);
  assert.equal(apiRequests.length, 0);
  const authenticated = await login(baseUrl, anonymous);
  const noCsrf = await fetch(`${baseUrl}/api/auth/google/analyze`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ messageId: 'selected-1' }),
  });
  assert.equal(noCsrf.status, 403);
  assert.equal(apiRequests.length, 0);

  const preview = await fetch(`${baseUrl}/api/auth/google/sync`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken },
  });
  assert.equal(preview.status, 200);
  assert.ok((await preview.json()).messages.some((message) => message.id === 'selected-1'));
  // The inbox can change after the user sees the preview. Analysis must use the
  // exact session-bound preview selection, not a fresh latest-five list.
  latestIds = ['newest-1', 'newest-2', 'newest-3', 'newest-4', 'newest-5'];
  const beforeAnalysis = apiRequests.length;

  const response = await fetch(`${baseUrl}/api/auth/google/analyze`, {
    method: 'POST', headers: { Origin: 'http://localhost:5173', Cookie: authenticated.cookie, 'X-CSRF-Token': authenticated.body.csrfToken, 'Content-Type': 'application/json' }, body: JSON.stringify({ messageId: 'selected-1' }),
  });
  assert.equal(response.status, 200);
  assert.equal(apiRequests.filter((item) => item.method === 'list').length, 1);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const result = await response.json();
  assert.deepEqual(Object.keys(result.message), ['id', 'sender', 'subject', 'date']);
  assert.deepEqual(Object.keys(result.analysis), ['score', 'riskLevel', 'indicators', 'explanation', 'uncertainty', 'recommendedActions']);
  assert.equal(result.analysis.riskLevel, 'high');
  assert.equal(JSON.stringify(result).includes(messageText), false);
  assert.doesNotMatch(JSON.stringify(result), /must not be returned|fictional-access-token/);
  assert.equal(apiRequests.length, beforeAnalysis + 3);
  assert.ok(apiRequests.slice(beforeAnalysis).every((item) => item.method === 'get' && item.parameters.id === 'selected-1'));
  assert.deepEqual(apiRequests[beforeAnalysis].parameters, { userId: 'me', id: 'selected-1', format: 'metadata', metadataHeaders: ['From', 'Subject', 'Date', 'Content-Disposition'], fields: 'id,payload/headers(name,value)' });
  assert.equal(apiRequests[beforeAnalysis + 1].parameters.format, 'full');
  assert.doesNotMatch(apiRequests[beforeAnalysis + 1].parameters.fields, /data|snippet|raw/);
  assert.match(apiRequests[beforeAnalysis + 1].parameters.fields, /headers\(name,value\)/);
  assert.equal(apiRequests[beforeAnalysis + 2].parameters.format, 'full');
  assert.doesNotMatch(apiRequests[beforeAnalysis + 2].parameters.fields, /snippet|raw/);
  assert.match(apiRequests[beforeAnalysis + 2].parameters.fields, /parts\(mimeType,filename,headers\(name,value\),body\(data,size,attachmentId\)/);
});
