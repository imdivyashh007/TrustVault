import test from 'node:test';
import assert from 'node:assert/strict';
import { requestGmailMetadataPreview, requestGmailMessageAnalysis } from '../src/gmailPreview.js';
import { gmailAnalysisReducer, initialGmailAnalysisState } from '../src/gmailAnalysisState.js';

test('preview request uses the authenticated POST endpoint and session CSRF token', async () => {
  let called;
  const fetchImpl = async (...args) => {
    called = args;
    return { ok: true, json: async () => ({ messages: [] }) };
  };

  const messages = await requestGmailMetadataPreview({ fetchImpl, csrfToken: 'test-csrf-token' });

  assert.deepEqual(called, ['/api/auth/google/sync', {
    method: 'POST',
    headers: { 'X-CSRF-Token': 'test-csrf-token' },
  }]);
  assert.deepEqual(messages, []);
});

test('preview response is limited to the five safe metadata fields', async () => {
  const fetchImpl = async () => ({
    ok: true,
    json: async () => ({ messages: [{
      id: 'fictional-id', sender: 'Fictional sender', subject: 'Hello', date: 'Wed, 22 Oct 2026',
      body: 'must never be rendered', snippet: 'must never be rendered', attachment: 'private',
    }] }),
  });

  const messages = await requestGmailMetadataPreview({ fetchImpl, csrfToken: 'csrf' });

  assert.deepEqual(messages, [{
    id: 'fictional-id', sender: 'Fictional sender', subject: 'Hello', date: 'Wed, 22 Oct 2026',
  }]);
});

test('preview errors use safe messages instead of raw server details', async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 502,
    json: async () => ({ error: 'secret token value: do-not-display' }),
  });

  await assert.rejects(
    requestGmailMetadataPreview({ fetchImpl, csrfToken: 'csrf' }),
    (error) => {
      assert.equal(error.message, 'TrustVault could not retrieve Gmail metadata. Try again later.');
      assert.equal(error.message.includes('do-not-display'), false);
      return true;
    },
  );
});

test('preview identifies expired Gmail authorization without exposing server text', async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ error: 'private provider error', reconnectRequired: true }),
  });

  await assert.rejects(
    requestGmailMetadataPreview({ fetchImpl, csrfToken: 'csrf' }),
    (error) => {
      assert.equal(error.reconnectRequired, true);
      assert.equal(error.unauthenticated, false);
      assert.match(error.message, /Gmail authorization expired/);
      assert.doesNotMatch(error.message, /private provider error/);
      return true;
    },
  );
});

test('preview rejects malformed or over-limit metadata safely', async (t) => {
  for (const payload of [{ messages: [{ id: 'missing-fields' }] }, { messages: Array.from({ length: 6 }, (_, index) => ({
    id: String(index), sender: 'Sender', subject: 'Subject', date: 'Date',
  })) }, null]) {
    await t.test('rejects malformed or excessive records', async () => {
      const fetchImpl = async () => ({ ok: true, json: async () => payload });
      await assert.rejects(
        requestGmailMetadataPreview({ fetchImpl, csrfToken: 'csrf' }),
        /invalid Gmail metadata preview/,
      );
    });
  }
});

test('selected-message analysis sends only the chosen ID with session CSRF and projects safe result fields', async () => {
  let called;
  const fetchImpl = async (...args) => {
    called = args;
    return { ok: true, json: async () => ({
      message: { id: 'fictional-id', sender: 'Fictional sender', subject: 'Notice', date: 'Date', body: 'must not be returned' },
      analysis: { score: 68, riskLevel: 'high', indicators: [{ code: 'otp-request', title: 'OTP request', detail: 'Do not share the code.' }], explanation: 'Combined warning signals.', uncertainty: 'Heuristic, not proof.', recommendedActions: ['Verify independently.'] },
      notice: 'Temporary only',
      token: 'must not be returned',
    }) };
  };
  const result = await requestGmailMessageAnalysis({ fetchImpl, csrfToken: 'csrf-test', messageId: 'fictional-id' });
  assert.deepEqual(called, ['/api/auth/google/analyze', {
    method: 'POST',
    headers: { 'X-CSRF-Token': 'csrf-test', 'Content-Type': 'application/json' },
    body: JSON.stringify({ messageId: 'fictional-id' }),
  }]);
  assert.deepEqual(result.message, { id: 'fictional-id', sender: 'Fictional sender', subject: 'Notice', date: 'Date' });
  assert.equal(result.analysis.riskLevel, 'high');
  assert.equal(JSON.stringify(result).includes('must not be returned'), false);
  assert.equal(JSON.stringify(result).includes('token'), false);
});

test('selected-message analysis maps server failures to safe UI messages', async () => {
  for (const [status, serverText, expected] of [
    [502, 'private provider response with token', /could not safely analyze/],
    [422, 'plain-text secret-body-value must not reach UI', /safety checks/],
  ]) {
    const fetchImpl = async () => ({ ok: false, status, json: async () => ({ error: serverText }) });
    await assert.rejects(requestGmailMessageAnalysis({ fetchImpl, csrfToken: 'csrf', messageId: 'fictional-id' }), (error) => {
      assert.match(error.message, expected);
      assert.doesNotMatch(error.message, /private provider|token|secret-body-value/);
      return true;
    });
  }
});

test('temporary Gmail analysis results clear on cancel, logout, disconnect, or view departure actions', () => {
  const selected = gmailAnalysisReducer(initialGmailAnalysisState, { type: 'confirm', message: { id: 'fictional-id' } });
  assert.equal(selected.target.id, 'fictional-id');
  const shown = gmailAnalysisReducer(selected, { type: 'success', result: { message: { id: 'fictional-id' }, analysis: { riskLevel: 'low' } } });
  assert.ok(shown.result);
  for (const action of [{ type: 'clear' }, { type: 'cancel' }]) {
    const cleared = gmailAnalysisReducer(shown, action);
    assert.deepEqual(cleared, initialGmailAnalysisState);
  }
  assert.deepEqual(gmailAnalysisReducer(shown, { type: 'confirm', message: { id: 'another-id' } }).result, null);
});
