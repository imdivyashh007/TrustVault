import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateIncidentReport } from '../incidentReport.js';
import { createIncidentReportHandler } from '../server.js';

const fixedTime = '2026-10-21T10:00:00.000Z';

test('incident report includes stored message details, local analysis, and generation time', () => {
  const report = generateIncidentReport({
    id: 'fictional-suspicious',
    sender: 'Fictional Campus IT',
    subject: 'Urgent account suspension',
    timestamp: '2026-10-20T09:30:00.000Z',
    source: 'Fictional email sample',
    body: 'Your account will be suspended immediately. Reveal your OTP at https://paypal.example.com/verify.',
  }, fixedTime);

  assert.equal(report.sender, 'Fictional Campus IT');
  assert.equal(report.subject, 'Urgent account suspension');
  assert.equal(report.timestamp, '2026-10-20T09:30:00.000Z');
  assert.equal(report.source, 'Fictional email sample');
  assert.match(report.messageText, /Reveal your OTP/);
  assert.equal(report.riskLevel, 'high');
  assert.ok(report.riskScore >= 55);
  assert.ok(report.indicators.some((indicator) => indicator.code === 'urgency'));
  assert.ok(report.indicators.some((indicator) => indicator.code === 'otp-request'));
  assert.ok(report.indicators.some((indicator) => indicator.code === 'suspicious-url'));
  assert.ok(report.indicators.every((indicator) => indicator.explanation));
  assert.ok(report.recommendedActions.some((action) => /one-time codes/.test(action)));
  assert.match(report.disclaimer, /not a probability/);
  assert.equal(report.generatedAt, fixedTime);
});

test('report recomputes analysis when a stored record has no analysis', () => {
  const report = generateIncidentReport({ sender: 'Campus Bookstore', body: 'Your order is ready for pickup.' }, fixedTime);
  assert.equal(report.riskLevel, 'low');
  assert.equal(report.riskScore, 0);
  assert.deepEqual(report.indicators, []);
});

test('empty message fields receive clear fallbacks and a safe report', () => {
  const report = generateIncidentReport({ sender: '', subject: '', body: '', date: '' }, fixedTime);
  assert.equal(report.sender, 'Unknown sender');
  assert.equal(report.subject, 'No subject');
  assert.equal(report.timestamp, 'Date unavailable');
  assert.equal(report.source, 'Source unavailable');
  assert.equal(report.messageText, 'No message text was provided.');
  assert.equal(report.riskLevel, 'low');
  assert.ok(report.recommendedActions.length > 0);
});

test('report endpoint builds a report for a message in the local store', async () => {
  let payload;
  const response = { json(value) { payload = value; return value; } };
  const storedMessage = { id: 'stored-message', sender: 'Fictional Bookstore', subject: 'Pickup', body: 'Your book is ready.' };
  await createIncidentReportHandler({ read: async () => [storedMessage] })({ params: { id: storedMessage.id } }, response, (error) => { throw error; });
  assert.equal(payload.report.sender, 'Fictional Bookstore');
  assert.equal(payload.report.riskLevel, 'low');
  assert.equal(payload.report.messageText, 'Your book is ready.');
  assert.ok(payload.report.generatedAt);
});

test('report endpoint responds clearly when message is not in the vault', async () => {
  let statusCode = 200;
  let payload;
  const response = {
    status(code) { statusCode = code; return this; },
    json(value) { payload = value; return value; },
  };
  await createIncidentReportHandler({ read: async () => [] })({ params: { id: 'missing-id' } }, response, (error) => { throw error; });
  assert.equal(statusCode, 404);
  assert.match(payload.error, /could not be found/);
});
