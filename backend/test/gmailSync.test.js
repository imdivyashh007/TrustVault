import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GMAIL_READONLY_SCOPE } from '../googleOAuth.js';
import { createGmailSyncHandler, createGmailSyncRateLimiter } from '../gmailSync.js';

const bundle = {
  version: 1,
  accessToken: 'fictional-access-token',
  refreshToken: 'fictional-refresh-token',
  expiryDate: Date.now() + 60_000,
  scopes: [GMAIL_READONLY_SCOPE],
};

function responseDouble() {
  return {
    statusCode: 200,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    set(name, value) { this.headers[name] = value; return this; },
    json(body) { this.body = body; return this; },
  };
}

function requestDouble() {
  return { socket: { remoteAddress: '127.0.0.1' } };
}

function handlerFor({ tokenStore = { read: async () => bundle }, gmailApiFactory = () => ({}) } = {}) {
  return createGmailSyncHandler({
    tokenStore,
    oauthClientFactory: () => ({ setCredentials() {}, on() {} }),
    gmailApiFactory,
    rateLimiter: createGmailSyncRateLimiter(),
    oauthConfig: {},
  });
}

test('Gmail sync limiter caps requests per local client and resets after its window', () => {
  let now = 1_000;
  const limiter = createGmailSyncRateLimiter({ maxRequests: 2, windowMs: 5_000, now: () => now });
  assert.equal(limiter.take('127.0.0.1').allowed, true);
  assert.equal(limiter.take('127.0.0.1').allowed, true);
  assert.deepEqual(limiter.take('127.0.0.1'), { allowed: false, retryAfterSeconds: 5 });
  now += 5_000;
  assert.equal(limiter.take('127.0.0.1').allowed, true);
});

test('Gmail sync refuses absent or unverifiable local token storage safely', async () => {
  const missingResponse = responseDouble();
  await handlerFor({ tokenStore: { read: async () => null } })(requestDouble(), missingResponse);
  assert.equal(missingResponse.statusCode, 409);
  assert.match(missingResponse.body.error, /Connect Gmail/);

  const corruptResponse = responseDouble();
  await handlerFor({ tokenStore: { read: async () => { throw new Error('private crypto detail'); } } })(requestDouble(), corruptResponse);
  assert.equal(corruptResponse.statusCode, 503);
  assert.doesNotMatch(JSON.stringify(corruptResponse.body), /private crypto detail/);
});

test('Gmail sync rejects broader scopes before creating a Gmail API client', async () => {
  let apiFactoryCalls = 0;
  const response = responseDouble();
  const broadScope = { ...bundle, scopes: [GMAIL_READONLY_SCOPE, 'https://mail.google.com/'] };
  await handlerFor({ tokenStore: { read: async () => broadScope }, gmailApiFactory: () => { apiFactoryCalls += 1; } })(requestDouble(), response);
  assert.equal(response.statusCode, 403);
  assert.equal(apiFactoryCalls, 0);
});

test('Gmail sync safely reports revoked authorization and malformed metadata', async () => {
  const revokedResponse = responseDouble();
  await handlerFor({ gmailApiFactory: () => ({ users: { messages: { list: async () => { throw { response: { status: 401 } }; } } } }) })(requestDouble(), revokedResponse);
  assert.equal(revokedResponse.statusCode, 401);
  assert.match(revokedResponse.body.error, /Reconnect Gmail/);
  assert.doesNotMatch(JSON.stringify(revokedResponse.body), /token/i);

  const malformedResponse = responseDouble();
  await handlerFor({ gmailApiFactory: () => ({ users: { messages: {
    list: async () => ({ data: { messages: [{ id: 'fictional-id' }] } }),
    get: async () => ({ data: { id: 'different-id', payload: { headers: [] } } }),
  } } }) })(requestDouble(), malformedResponse);
  assert.equal(malformedResponse.statusCode, 502);
  assert.match(malformedResponse.body.error, /metadata preview/);
});

test('Gmail sync fails closed if refreshed credentials cannot be persisted', async () => {
  let tokenListener;
  const tokenStore = {
    read: async () => bundle,
    write: async () => { throw new Error('private storage failure'); },
  };
  const oauthClientFactory = () => ({ setCredentials() {}, on(_event, listener) { tokenListener = listener; } });
  const gmailApiFactory = () => ({ users: { messages: {
    list: async () => {
      tokenListener({ access_token: 'fictional-rotated-token', expiry_date: Date.now() + 120_000 });
      return { data: { messages: [] } };
    },
  } } });
  const handler = createGmailSyncHandler({
    tokenStore, oauthClientFactory, gmailApiFactory,
    rateLimiter: createGmailSyncRateLimiter(), oauthConfig: {},
  });
  const response = responseDouble();
  await handler(requestDouble(), response);
  assert.equal(response.statusCode, 503);
  assert.match(response.body.error, /could not be safely saved locally/);
  assert.doesNotMatch(JSON.stringify(response.body), /fictional-rotated-token|private storage failure/);
});
