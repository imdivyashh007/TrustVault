import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GMAIL_READONLY_SCOPE } from '../googleOAuth.js';
import { createGmailAnalysisHandler, createGmailAnalysisRateLimiter, GMAIL_ANALYSIS_MAX_BODY_BYTES } from '../gmailAnalysis.js';
import { createGmailPreviewRegistry } from '../gmailPreviewRegistry.js';
import { createGmailSyncRateLimiter } from '../gmailSync.js';

const bundle = { version: 1, accessToken: 'fictional-access-token', refreshToken: 'fictional-refresh-token', expiryDate: Date.now() + 60_000, scopes: [GMAIL_READONLY_SCOPE] };
const previewIds = ['fictional-1', 'fictional-2', 'fictional-3', 'fictional-4', 'fictional-5'];

function responseDouble() {
  return { statusCode: 200, headers: {}, status(code) { this.statusCode = code; return this; }, set(name, value) { this.headers[name] = value; return this; }, json(body) { this.body = body; return this; } };
}

function gmailResponse(id, payload, extra = {}) { return { data: { id, payload, ...extra } }; }
function headers(extra = []) { return [
  { name: 'From', value: 'Campus Support <support@example.com>' },
  { name: 'Subject', value: 'Account notice' },
  { name: 'Date', value: 'Thu, 22 Oct 2026 10:00:00 +0000' },
  ...extra,
]; }
function mimePart(mimeType, content, { includeData = true, filename = '', partHeaders = [] } = {}) {
  const bytes = Buffer.from(content, 'utf8');
  return {
    mimeType,
    filename,
    headers: [{ name: 'Content-Type', value: mimeType }, ...partHeaders],
    body: {
      size: bytes.length,
      ...(includeData ? { data: bytes.toString('base64url') } : {}),
    },
    parts: [],
  };
}
function alternativePayload({ includeData = true, plainText = 'A friendly note for myself.', htmlText = '<html><body><p>hello</p></body></html>', parts } = {}) {
  return {
    mimeType: 'multipart/alternative',
    filename: '',
    body: { size: 0 },
    parts: parts || [
      mimePart('text/plain', plainText, { includeData }),
      mimePart('text/html', htmlText, { includeData }),
    ],
  };
}
function makeHandler({ token = bundle, previewIdsForSession = previewIds, discoveryPayload, contentPayload, metadataHeaders = headers(), apiFailure, maxRequests = 5 } = {}) {
  const calls = [];
  let tokensListener;
  const tokenWrites = [];
  const tokenStore = { read: async () => token, write: async (value) => { tokenWrites.push(value); } };
  const gmailApiFactory = () => ({ users: { messages: {
    async get(parameters) {
      calls.push({ method: 'get', parameters });
      if (apiFailure) throw apiFailure;
      if (parameters.format === 'metadata') return gmailResponse(parameters.id, { headers: metadataHeaders }, { snippet: 'ignored snippet' });
      if (parameters.fields.includes('body(data')) return gmailResponse(parameters.id, contentPayload || {
        mimeType: 'text/plain', body: { size: Buffer.byteLength('Your account will be suspended. Reveal your OTP at https://example.com/verify now.'), data: Buffer.from('Your account will be suspended. Reveal your OTP at https://example.com/verify now.').toString('base64url') },
      }, { snippet: 'ignored snippet', raw: 'ignored raw' });
      return gmailResponse(parameters.id, discoveryPayload || { mimeType: 'text/plain', body: { size: 80 }, parts: [] }, { snippet: 'ignored snippet' });
    },
  } } });
  const previewRegistry = createGmailPreviewRegistry();
  previewRegistry.remember('fictional-session', previewIdsForSession);
  const handler = createGmailAnalysisHandler({
    tokenStore,
    oauthClientFactory: () => ({ setCredentials() {}, on(event, listener) { assert.equal(event, 'tokens'); tokensListener = listener; } }),
    gmailApiFactory,
    rateLimiter: createGmailAnalysisRateLimiter({ maxRequests, windowMs: 60_000 }),
    oauthConfig: {},
    previewRegistry,
  });
  return { handler, calls, tokenWrites, tokenListener: () => tokensListener };
}

function request(messageId = 'fictional-1') { return { body: { messageId }, socket: { remoteAddress: '127.0.0.1' }, trustVaultSession: { id: 'fictional-session' } }; }

test('analyzes one explicitly selected recent message with safe plain-text-only Gmail requests', async () => {
  const { handler, calls } = makeHandler();
  const response = responseDouble();
  await handler(request(), response);
  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map(({ parameters }) => [parameters.id, parameters.format]), [['fictional-1', 'metadata'], ['fictional-1', 'full'], ['fictional-1', 'full']]);
  assert.deepEqual(calls[0].parameters.metadataHeaders, ['From', 'Subject', 'Date', 'Content-Disposition']);
  assert.equal(calls[0].parameters.fields, 'id,payload/headers(name,value)');
  assert.match(calls[1].parameters.fields, /body\(attachmentId,size\)/);
  assert.doesNotMatch(calls[1].parameters.fields, /data|snippet|raw/);
  assert.match(calls[1].parameters.fields, /parts\(mimeType,filename,headers\(name,value\)/);
  assert.match(calls[2].parameters.fields, /body\(data,size,attachmentId\)/);
  assert.doesNotMatch(calls[2].parameters.fields, /snippet|raw/);
  assert.match(calls[2].parameters.fields, /parts\(mimeType,filename,headers\(name,value\)/);
  assert.deepEqual(Object.keys(response.body), ['message', 'analysis', 'notice']);
  assert.equal(response.body.analysis.riskLevel, 'high');
  assert.ok(response.body.analysis.indicators.some((indicator) => indicator.code === 'otp-request'));
  assert.match(response.body.analysis.uncertainty, /not a probability and not proof/);
  assert.equal(JSON.stringify(response.body).includes('Your account will be suspended'), false);
  assert.equal(JSON.stringify(response.body).includes('ignored snippet'), false);
  assert.equal(JSON.stringify(response.body).includes('fictional-access-token'), false);
});

test('the selected plain-text body drives link-language warnings and a safe next step', async () => {
  const text = 'Click here to verify your account immediately or access will be suspended.';
  const { handler } = makeHandler({ contentPayload: {
    mimeType: 'text/plain',
    body: { size: Buffer.byteLength(text), data: Buffer.from(text).toString('base64url') },
  } });
  const response = responseDouble();
  await handler(request(), response);
  assert.equal(response.statusCode, 200);
  assert.ok(response.body.analysis.indicators.some(({ code }) => code === 'suspicious-link-language'));
  assert.match(response.body.analysis.explanation, /link/);
  assert.ok(response.body.analysis.recommendedActions.some((action) => /Avoid opening the link/.test(action)));
});

test('accepts a safe multipart alternative and analyzes only its text/plain part', async () => {
  const plainText = 'A friendly note for myself.';
  const htmlText = '<html><body>URGENT: Account suspended. Reveal your OTP at https://example.com/verify immediately.</body></html>';
  const discoveryPayload = alternativePayload({ includeData: false, plainText, htmlText });
  const contentPayload = alternativePayload({ includeData: true, plainText, htmlText });
  const { handler, calls } = makeHandler({ discoveryPayload, contentPayload });
  const response = responseDouble();

  await handler(request(), response);

  assert.equal(response.statusCode, 200);
  assert.equal(response.body.analysis.riskLevel, 'low');
  assert.deepEqual(response.body.analysis.indicators, []);
  assert.match(response.body.analysis.explanation, /cannot establish that the message is safe/);
  assert.ok(response.body.analysis.recommendedActions.some((action) => /does not establish that the message is safe/.test(action)));
  assert.equal(JSON.stringify(response.body).includes(plainText), false);
  assert.equal(JSON.stringify(response.body).includes(htmlText), false);
  assert.equal(calls.length, 3);
  assert.doesNotMatch(calls[1].parameters.fields, /data|snippet|raw/);
  assert.match(calls[2].parameters.fields, /parts\(mimeType,filename,headers\(name,value\),body\(data,size,attachmentId\)/);
  assert.doesNotMatch(calls[2].parameters.fields, /snippet|raw|payload\/headers/);
});

test('rejects IDs absent from this authenticated session preview without Gmail requests', async () => {
  const { handler, calls } = makeHandler();
  const response = responseDouble();
  await handler(request('not-in-preview'), response);
  assert.equal(response.statusCode, 404);
  assert.equal(calls.length, 0);
});

test('accepts an ID from the displayed preview even if the live top-five list would have changed', async () => {
  const { handler, calls } = makeHandler({ previewIdsForSession: ['fictional-1', 'fictional-2', 'fictional-3', 'fictional-4', 'fictional-5'] });
  const response = responseDouble();
  await handler(request('fictional-1'), response);
  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 3);
  assert.ok(calls.every((call) => call.method === 'get' && call.parameters.id === 'fictional-1'));
});

test('preview IDs are isolated by session and expire', () => {
  let now = 1_000;
  const registry = createGmailPreviewRegistry({ ttlMs: 100, now: () => now });
  assert.equal(registry.remember('session-a', ['preview-id']), true);
  assert.equal(registry.has('session-a', 'preview-id'), true);
  assert.equal(registry.has('session-b', 'preview-id'), false);
  now += 100;
  assert.equal(registry.has('session-a', 'preview-id'), false);
});

test('analysis allows three requests per client IP per minute; preview uses a separate limiter', () => {
  let now = 1_000;
  const analysisLimiter = createGmailAnalysisRateLimiter({ now: () => now });
  const previewLimiter = createGmailSyncRateLimiter({ now: () => now });

  assert.equal(analysisLimiter.take('127.0.0.1').allowed, true);
  assert.equal(analysisLimiter.take('127.0.0.1').allowed, true);
  assert.equal(analysisLimiter.take('127.0.0.1').allowed, true);
  assert.deepEqual(analysisLimiter.take('127.0.0.1'), { allowed: false, retryAfterSeconds: 60 });
  assert.equal(analysisLimiter.take('::1').allowed, true, 'another socket address has its own budget');
  assert.equal(previewLimiter.take('127.0.0.1').allowed, true, 'preview traffic has an independent limiter');

  now += 60_000;
  assert.equal(analysisLimiter.take('127.0.0.1').allowed, true, 'the fixed window resets after one minute');
});

test('analysis rejects a preview ID presented from a different authenticated session', async () => {
  const { handler, calls } = makeHandler();
  const response = responseDouble();
  await handler({ ...request(), trustVaultSession: { id: 'different-session' } }, response);
  assert.equal(response.statusCode, 404);
  assert.equal(calls.length, 0);
});

test('rejects missing token storage and unexpected scopes before Gmail API calls', async (t) => {
  for (const token of [null, { ...bundle, scopes: [GMAIL_READONLY_SCOPE, 'https://mail.google.com/'] }]) {
    await t.test(token ? 'reject broader scope' : 'reject missing token', async () => {
      const { handler, calls } = makeHandler({ token });
      const response = responseDouble();
      await handler(request(), response);
      assert.ok([403, 409].includes(response.statusCode));
      assert.equal(calls.length, 0);
    });
  }
});

test('rejects multipart, HTML, filename, attachment IDs, and attachment disposition before body fetch', async (t) => {
  const cases = [
    ['multipart', { mimeType: 'multipart/alternative', body: { size: 10 }, parts: [{ mimeType: 'text/plain' }] }],
    ['HTML', { mimeType: 'text/html', body: { size: 10 }, parts: [] }],
    ['filename', { mimeType: 'text/plain', filename: 'message.txt', body: { size: 10 }, parts: [] }],
    ['malformed filename', { mimeType: 'text/plain', filename: 9, body: { size: 10 }, parts: [] }],
    ['missing MIME body size', { mimeType: 'text/plain', body: {}, parts: [] }],
    ['attachment ID', { mimeType: 'text/plain', body: { attachmentId: 'external-attachment', size: 10 }, parts: [] }],
    ['attachment disposition', { mimeType: 'text/plain', body: { size: 10 }, parts: [] }],
    ['inline MIME parts', { mimeType: 'text/plain', body: { size: 10 }, parts: [{ mimeType: 'image/png' }] }],
  ];
  for (const [label, payload] of cases) await t.test(label, async () => {
    const { handler, calls } = makeHandler({
      discoveryPayload: payload,
      metadataHeaders: label === 'attachment disposition' ? headers([{ name: 'Content-Disposition', value: 'attachment; filename="x.txt"' }]) : headers(),
    });
    const response = responseDouble();
    await handler(request(), response);
    assert.equal(response.statusCode, 422);
    assert.equal(calls.length, label === 'attachment disposition' ? 1 : 2, 'body data must not be requested for rejected messages');
    assert.match(response.body.error, /not|attachment|MIME|supported|exceeds/i);
  });
});

test('rejects HTML-only, attachment-bearing, nested, malformed, and oversized multipart alternatives', async (t) => {
  const safePlain = 'A friendly note.';
  const safeHtml = '<html><body>A friendly note.</body></html>';
  const cases = [
    ['HTML-only alternative', alternativePayload({ includeData: false, parts: [
      mimePart('text/html', safeHtml, { includeData: false }),
    ] }), undefined, 2],
    ['extra attachment part', alternativePayload({ includeData: false, parts: [
      mimePart('text/plain', safePlain, { includeData: false }),
      mimePart('text/html', safeHtml, { includeData: false }),
      mimePart('application/pdf', 'file', { includeData: false, filename: 'note.pdf' }),
    ] }), undefined, 2],
    ['attachment disposition', alternativePayload({ includeData: false, parts: [
      mimePart('text/plain', safePlain, { includeData: false, partHeaders: [{ name: 'Content-Disposition', value: 'attachment' }] }),
      mimePart('text/html', safeHtml, { includeData: false }),
    ] }), undefined, 2],
    ['nested inline part', alternativePayload({ includeData: false, parts: [
      mimePart('text/plain', safePlain, { includeData: false }),
      { ...mimePart('text/html', safeHtml, { includeData: false }), parts: [{ mimeType: 'image/png' }] },
    ] }), undefined, 2],
    ['combined alternatives exceed 64 KB', alternativePayload({ includeData: false, parts: [
      { ...mimePart('text/plain', safePlain, { includeData: false }), body: { size: 40 * 1024 } },
      { ...mimePart('text/html', safeHtml, { includeData: false }), body: { size: 25 * 1024 } },
    ] }), undefined, 2],
    ['malformed plain-text base64url', alternativePayload({ includeData: false, parts: [
      { ...mimePart('text/plain', 'abc', { includeData: false }), body: { size: 3 } },
      mimePart('text/html', safeHtml, { includeData: false }),
    ] }), alternativePayload({ includeData: true, parts: [
      { ...mimePart('text/plain', 'abc'), body: { size: 3, data: '%%%bad' } },
      mimePart('text/html', safeHtml),
    ] }), 3],
    ['plain-text byte count mismatch', alternativePayload({ includeData: false, parts: [
      { ...mimePart('text/plain', 'abc', { includeData: false }), body: { size: 4 } },
      mimePart('text/html', safeHtml, { includeData: false }),
    ] }), alternativePayload({ includeData: true, parts: [
      { ...mimePart('text/plain', 'abc'), body: { size: 4, data: Buffer.from('abc').toString('base64url') } },
      mimePart('text/html', safeHtml),
    ] }), 3],
    ['oversized decoded plain text', alternativePayload({ includeData: false, parts: [
      { ...mimePart('text/plain', safePlain, { includeData: false }), body: { size: GMAIL_ANALYSIS_MAX_BODY_BYTES + 1 } },
      mimePart('text/html', safeHtml, { includeData: false }),
    ] }), undefined, 2],
  ];

  for (const [label, discoveryPayload, contentPayload, expectedCalls] of cases) await t.test(label, async () => {
    const { handler, calls } = makeHandler({ discoveryPayload, contentPayload });
    const response = responseDouble();
    await handler(request(), response);
    assert.equal(response.statusCode, 422);
    assert.equal(calls.length, expectedCalls, 'unsafe structures are rejected before requesting or analyzing further content');
    assert.match(response.body.error, /attachment|MIME|alternative|plain-text|64 KB|malformed/i);
  });
});

test('rejects oversized, malformed, invalid UTF-8, and empty body data', async (t) => {
  const structure = { mimeType: 'text/plain', body: { size: 10 }, parts: [] };
  const cases = [
    ['oversized declared structure', { mimeType: 'text/plain', body: { size: GMAIL_ANALYSIS_MAX_BODY_BYTES + 1 }, parts: [] }, undefined],
    ['oversized decoded body', structure, { mimeType: 'text/plain', body: { size: GMAIL_ANALYSIS_MAX_BODY_BYTES + 1, data: Buffer.alloc(GMAIL_ANALYSIS_MAX_BODY_BYTES + 1, 65).toString('base64url') }, parts: [] }],
    ['malformed base64url', structure, { mimeType: 'text/plain', body: { size: 5, data: '%%%bad' }, parts: [] }],
    ['invalid UTF-8', structure, { mimeType: 'text/plain', body: { size: 2, data: Buffer.from([0xc3, 0x28]).toString('base64url') }, parts: [] }],
    ['empty body', structure, { mimeType: 'text/plain', body: { size: 0, data: '' }, parts: [] }],
    ['HTML-like body', structure, { mimeType: 'text/plain', body: { size: Buffer.byteLength('<html><script>unsafe</script></html>'), data: Buffer.from('<html><script>unsafe</script></html>').toString('base64url') }, parts: [] }],
  ];
  for (const [label, discoveryPayload, contentPayload] of cases) await t.test(label, async () => {
    const { handler, calls } = makeHandler({ discoveryPayload, contentPayload });
    const response = responseDouble();
    await handler(request(), response);
    assert.equal(response.statusCode, 422);
    if (label === 'oversized declared structure') assert.equal(calls.length, 2);
    else assert.equal(calls.length, 3);
  });
});

test('handles Gmail errors without exposing provider details and applies a rate limit', async () => {
  const providerError = { response: { status: 403, data: { error_description: 'private-token-and-message-detail' } } };
  const failing = makeHandler({ apiFailure: providerError }).handler;
  const providerResponse = responseDouble();
  await failing(request(), providerResponse);
  assert.equal(providerResponse.statusCode, 401);
  assert.doesNotMatch(JSON.stringify(providerResponse.body), /private-token-and-message-detail/);

  const { handler } = makeHandler({ maxRequests: 1 });
  await handler(request(), responseDouble());
  const limited = responseDouble();
  await handler(request(), limited);
  assert.equal(limited.statusCode, 429);
  assert.ok(Number(limited.headers['Retry-After']) > 0);
});
