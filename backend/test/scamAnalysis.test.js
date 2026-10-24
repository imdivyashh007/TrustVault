import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { analyzeMessage, analyzeMessages, withMessageAnalysis } from '../scamAnalysis.js';

const hasIndicator = (analysis, code) => analysis.indicators.some((indicator) => indicator.code === code);

test('benign messages score low without warning signals', () => {
  const analysis = analyzeMessage({
    sender: 'Study Group',
    subject: 'Meeting moved to 3 PM',
    body: 'Let’s meet in the library Thursday to review the slides.',
  });
  assert.equal(analysis.score, 0);
  assert.equal(analysis.riskLevel, 'low');
  assert.equal(analysis.indicators.length, 0);
  assert.match(analysis.disclaimer, /not a probability/);
});

test('urgent phishing pressure combined with credentials and a deceptive URL is high risk', () => {
  const analysis = analyzeMessage({
    sender: 'Campus IT',
    subject: 'Urgent account suspension',
    body: 'Act now or your account will be disabled. Verify your password at https://microsoft.security-check.example/login',
  });
  assert.equal(analysis.riskLevel, 'high');
  assert.ok(analysis.score >= 55);
  assert.ok(hasIndicator(analysis, 'urgency'));
  assert.ok(hasIndicator(analysis, 'credential-request'));
  assert.ok(hasIndicator(analysis, 'suspicious-url'));
  assert.ok(analysis.recommendedActions.some((action) => /passwords/.test(action)));
});

test('fictional account suspension message requests an OTP and suspicious link', () => {
  const analysis = analyzeMessage({
    sender: 'Fictional Campus IT',
    subject: 'Urgent: account suspension',
    body: 'Your account will be suspended immediately. Follow this link and reveal your OTP: https://paypal.example.com/verify',
  });
  assert.equal(analysis.riskLevel, 'high');
  assert.ok(hasIndicator(analysis, 'urgency'));
  assert.ok(hasIndicator(analysis, 'otp-request'));
  assert.ok(hasIndicator(analysis, 'suspicious-url'));
  assert.ok(analysis.recommendedActions.some((action) => /one-time codes/.test(action)));
  assert.ok(analysis.recommendedActions.some((action) => /Avoid opening the link/.test(action)));
});

test('a verification URL alone does not count as a credential request', () => {
  const analysis = analyzeMessage({
    sender: 'Campus IT',
    body: 'Please review the account notice at https://campus.example/verify',
  });
  assert.ok(!hasIndicator(analysis, 'otp-request'));
  assert.ok(!hasIndicator(analysis, 'credential-request'));
});

test('clear account verification link language is warned on while ordinary text stays limited low risk', () => {
  const suspicious = analyzeMessage({ body: 'Click here to sign in and verify your account immediately.' });
  assert.ok(hasIndicator(suspicious, 'suspicious-link-language'));
  assert.ok(suspicious.recommendedActions.some((action) => /Avoid opening the link/.test(action)));

  const harmless = analyzeMessage({ body: 'Thanks for sharing the meeting notes. See you Thursday.' });
  assert.equal(harmless.score, 0);
  assert.equal(harmless.indicators.length, 0);
  assert.ok(harmless.recommendedActions.some((action) => /does not establish that the message is safe/.test(action)));
});

test('the existing Campus Bookstore demo message has a low-risk assessment', async () => {
  const messages = JSON.parse(await readFile(new URL('../data/messages.json', import.meta.url), 'utf8'));
  const bookstore = analyzeMessages(messages).find((message) => message.id === 'demo-1');
  assert.ok(bookstore);
  assert.equal(bookstore.analysis.riskLevel, 'low');
  assert.equal(bookstore.analysis.score, 0);
  assert.equal(bookstore.analysis.indicators.length, 0);
});

test('one-time code requests are explained and produce medium or high risk', () => {
  const analysis = analyzeMessage({
    sender: 'Unknown number',
    subject: 'Verification',
    body: 'Reply with the one-time passcode we sent you.',
  });
  assert.ok(['medium', 'high'].includes(analysis.riskLevel));
  assert.ok(hasIndicator(analysis, 'otp-request'));
  assert.ok(analysis.recommendedActions.some((action) => /one-time codes/.test(action)));
});

test('unexpected money and gift-card requests are detected without relying on urgency', () => {
  const analysis = analyzeMessage({
    sender: 'Fictional Manager',
    subject: 'Quick favor',
    body: 'Please buy gift cards and send me the codes.',
  });
  assert.ok(['medium', 'high'].includes(analysis.riskLevel));
  assert.ok(hasIndicator(analysis, 'gift-card-payment'));
  assert.ok(analysis.recommendedActions.some((action) => /gift cards/.test(action)));

  const transfer = analyzeMessage({ sender: 'Unknown', body: 'Please transfer $250 to this account.' });
  assert.ok(hasIndicator(transfer, 'payment-request'));
  assert.equal(transfer.riskLevel, 'medium');
});

test('deceptive domains and raw IP links are suspicious; URL is extracted from message content', () => {
  const analysis = analyzeMessage({
    sender: 'Delivery Desk',
    subject: 'Package held',
    body: 'Click to verify your address: http://192.0.2.10/confirm',
  });
  assert.ok(hasIndicator(analysis, 'suspicious-url'));
  assert.ok(hasIndicator(analysis, 'claim-with-action'));
  assert.ok(analysis.score >= 55);
});

test('delivery, account, refund, and prize claims gain a signal only when tied to sensitive data or a suspicious URL', () => {
  const examples = [
    { sender: 'Delivery Desk', body: 'Package held. Verify your address at http://192.0.2.9/track' },
    { sender: 'Account Team', body: 'Your account will be suspended. Enter your password at https://account-security-paypal.example/login' },
    { sender: 'Refund Center', body: 'Your refund is ready. Verify your bank details at https://refund-chase.example/confirm' },
    { sender: 'Prize Desk', body: 'Claim your prize by entering your card details at https://winner-amazon.example/claim' },
  ];
  for (const message of examples) {
    const analysis = analyzeMessage(message);
    assert.ok(hasIndicator(analysis, 'claim-with-action'), message.body);
  }

  const ordinaryClaimLink = analyzeMessage({
    sender: 'Campus Mailroom',
    body: 'Your package is ready. Click the campus portal link: https://campus.example/parcel',
  });
  assert.equal(ordinaryClaimLink.riskLevel, 'low');
  assert.ok(!hasIndicator(ordinaryClaimLink, 'claim-with-action'));
});

test('URL metadata is analyzed even if the URL is not repeated in the message body', () => {
  const analysis = analyzeMessage({
    sender: 'Campus IT',
    body: 'Please review this account notice.',
    urls: [{ url: 'https://accounts-google.example/verify' }],
  });
  assert.ok(hasIndicator(analysis, 'suspicious-url'));
});

test('a normal message containing an ordinary link and a payment mention stays low risk', () => {
  const analysis = analyzeMessage({
    sender: 'Campus Cafe',
    subject: 'Menu and payment options',
    body: 'Here is the menu and payment information for next week: https://campuscafe.example/menu',
  });
  assert.equal(analysis.riskLevel, 'low');
  assert.equal(analysis.indicators.length, 0);

  const informational = analyzeMessage({ sender: 'Student Finance Office', body: 'Read our guide to money transfer options and payment methods.' });
  assert.equal(informational.riskLevel, 'low');
  assert.ok(!hasIndicator(informational, 'payment-request'));
});

test('sender and subject are analyzed and urgent language alone is not enough to flag a message', () => {
  const analysis = analyzeMessage({
    sender: 'Student Events',
    subject: 'Urgent: please RSVP today',
    body: 'We need the final headcount for the campus picnic.',
  });
  assert.equal(analysis.riskLevel, 'low');
  assert.ok(hasIndicator(analysis, 'urgency'));
});

test('demo and imported records receive the same structured local analysis', async () => {
  const messages = JSON.parse(await readFile(new URL('../data/messages.json', import.meta.url), 'utf8'));
  const analyzed = analyzeMessages(messages);
  assert.equal(analyzed.length, messages.length);
  assert.ok(analyzed.every((message) => message.analysis && ['low', 'medium', 'high'].includes(message.analysis.riskLevel)));
  const imported = withMessageAnalysis({ id: 'import-demo', sender: 'Cafe', body: 'Your order is ready.', subject: 'Pickup', source: 'Fictional email sample' });
  assert.equal(imported.analysis.riskLevel, 'low');
  assert.equal(imported.analysisStatus, 'safe');
});
