const URGENCY = /\b(act now|act immediately|immediately|urgent(?:ly)?|right now|right away|within (?:\d+|one|two|three) (?:seconds?|minutes?|hours?)|in (?:\d+|one|two|three) (?:minutes?|hours?)|final notice|last warning|expires? today|avoid (?:suspension|closure|deactivation)|will be (?:closed|suspended|disabled)|account (?:will be )?(?:locked|suspended|closed)|legal action|permanently deleted)\b/i;
const CREDENTIAL_REQUEST = /\b(passwords?|passcodes?|login(?: details| credentials?| information)?|credentials?|one[- ]time (?:passcodes?|codes?)|\botp\b|verification codes?|security codes?|mfa codes?)\b/i;
const OTP = /\b(one[- ]time (?:passcodes?|codes?)|\botp\b|verification codes?|security codes?|mfa codes?)\b/i;
const ASKS_FOR_SECRET = /\b(share|send|reply with|provide|enter|submit|confirm|verify|type|tell us|give us|reveal|disclose)\b[^.!?\n]{0,90}\b(password|passcode|credentials?|one[- ]time code|verification code|security code|otp|login)\b|\b(password|passcode|credentials?|one[- ]time code|verification code|security code|otp)\b[^.!?\n]{0,90}\b(share|send|reply|provide|enter|submit|confirm|verify|type|tell us|give us|reveal|disclose)\b/i;
const SENSITIVE_INFO_REQUEST = /\b(verify|confirm|update|provide|enter|submit|send|reply with)\b[^.!?\n]{0,80}\b(address|date of birth|social security|bank|card|account details|personal information|identity|billing details)\b/i;
const PAYMENT_REQUEST = /\b(send|transfer|wire|pay|deposit|purchase|buy|forward|zelle|venmo|cash ?app)\b[^.!?\n]{0,90}(?:\$\s?\d|\b(?:money|cash|funds|gift cards?|crypto(?:currency)?|bitcoin)\b)|\b(?:gift cards?|crypto(?:currency)?|bitcoin|money|funds)\b[^.!?\n]{0,90}\b(send|pay|purchase|buy|forward)\b/i;
const GIFT_CARD_REQUEST = /\b(gift cards?|itunes cards?|google play cards?|steam cards?)\b/i;
const SUSPICIOUS_LINK_LANGUAGE = /\b(?:click|tap|follow|open|use)\b[^.!?\n]{0,70}\b(?:link|button|here|below)\b[^.!?\n]{0,90}\b(?:verify|confirm|unlock|restore|sign[ -]?in|log[ -]?in|password|account|payment|claim|secure)\b|\b(?:verify|confirm|unlock|restore|sign[ -]?in|log[ -]?in)\b[^.!?\n]{0,70}\b(?:link|button|here|below)\b/i;
const CLAIM = /\b(delivery|package|shipment|parcel|account|refund|prize|reward|tax return|reimbursement)\b/i;
const CLAIM_PROBLEM = /\b(held|failed|delayed|suspended|locked|closed|disabled|refund|prize|reward|claim|on hold|verify|confirm|release)\b/i;
const URL_PATTERN = /(?:https?:\/\/|www\.)[^\s<>"']+/gi;
const URL_SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'tiny.cc', 'is.gd', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'lnkd.in']);
const BRAND_DOMAINS = {
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.in'],
  apple: ['apple.com'],
  google: ['google.com', 'google.co.uk', 'google.ca', 'google.in'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com'],
  paypal: ['paypal.com'],
  netflix: ['netflix.com'],
  fedex: ['fedex.com'],
  ups: ['ups.com'],
  usps: ['usps.com'],
  dhl: ['dhl.com'],
  chase: ['chase.com'],
  venmo: ['venmo.com'],
};

const DISCLAIMER = 'This score is a local heuristic, not a probability. It does not prove that a message is fraudulent.';

/** Analyze a message locally using readable, explainable rules. */
export function analyzeMessage(message = {}) {
  const sourceText = [message.sender, message.subject, message.body, message.preview].filter(Boolean).join('\n');
  // A verb such as "verify" inside a URL path must not make nearby text look
  // like a request for credentials. Evaluate language signals on message text.
  const languageText = sourceText.replace(URL_PATTERN, ' ');
  const indicators = [];
  let score = 0;

  const urgency = URGENCY.test(languageText);
  const secretMention = CREDENTIAL_REQUEST.test(languageText);
  const secretRequest = secretMention && ASKS_FOR_SECRET.test(languageText);
  const otpRequest = secretRequest && OTP.test(languageText);
  const sensitiveRequest = secretRequest || SENSITIVE_INFO_REQUEST.test(languageText);
  const paymentRequest = PAYMENT_REQUEST.test(languageText);
  const suspiciousLinkLanguage = SUSPICIOUS_LINK_LANGUAGE.test(languageText);
  const suspiciousUrls = collectUrls(message).map(inspectUrl).filter((item) => item?.suspicious);
  const claims = CLAIM.test(languageText) && CLAIM_PROBLEM.test(languageText);
  const suspiciousClaim = claims && (sensitiveRequest || suspiciousUrls.length > 0);

  if (urgency) addIndicator(indicators, 'urgency', 'Pressure to act quickly', 'The message uses immediate deadlines or consequences that may discourage careful checking.', 12);
  if (secretRequest) addIndicator(indicators, otpRequest ? 'otp-request' : 'credential-request', otpRequest ? 'Request for a one-time or verification code' : 'Request for passwords or login credentials', 'Legitimate services generally will not ask you to send a password or one-time code in a message.', otpRequest ? 48 : 42);
  if (SENSITIVE_INFO_REQUEST.test(languageText) && !secretRequest) addIndicator(indicators, 'personal-info-request', 'Request for sensitive personal or account information', 'The message asks you to verify or provide information such as an address, bank, card, or account detail.', 30);
  if (paymentRequest) addIndicator(indicators, GIFT_CARD_REQUEST.test(languageText) ? 'gift-card-payment' : 'payment-request', GIFT_CARD_REQUEST.test(languageText) ? 'Unexpected gift-card or voucher payment request' : 'Request to send or transfer money', 'Unexpected payment instructions should be verified independently before you act.', GIFT_CARD_REQUEST.test(languageText) ? 48 : 38);
  for (const url of suspiciousUrls) addIndicator(indicators, 'suspicious-url', 'Suspicious-looking web address', url.reason, url.weight);
  if (suspiciousLinkLanguage) addIndicator(indicators, 'suspicious-link-language', 'Link asks you to verify or access an account', 'The message directs you through a link to verify, sign in, or change account access. Open the official site or app yourself instead.', 30);
  if (suspiciousClaim) addIndicator(indicators, 'claim-with-action', 'Delivery, account, refund, or prize claim tied to a risky action', 'The claim is paired with a request for sensitive information or a suspicious link, a common phishing pattern.', 18);

  const hasActionableRisk = indicators.some((indicator) => ['credential-request', 'otp-request', 'personal-info-request', 'payment-request', 'gift-card-payment', 'suspicious-url', 'suspicious-link-language', 'claim-with-action'].includes(indicator.code));
  if (urgency && hasActionableRisk) {
    indicators.push({ code: 'pressure-plus-request', title: 'Pressure combined with a risky request', detail: 'A deadline alongside a request for credentials, money, or a suspicious link is more concerning than either signal alone.', weight: 12 });
  }
  score += indicators.reduce((total, indicator) => total + indicator.weight, 0);
  score = Math.min(score, 100);

  const riskLevel = score >= 55 ? 'high' : score >= 25 ? 'medium' : 'low';
  return {
    score,
    riskLevel,
    indicators,
    recommendedActions: recommendations(indicators),
    disclaimer: DISCLAIMER,
  };
}

export function withMessageAnalysis(message) {
  const analysis = analyzeMessage(message);
  const analysisStatus = analysis.riskLevel === 'high' ? 'scam' : analysis.riskLevel === 'medium' ? 'review' : 'safe';
  const analysisNote = analysis.indicators.length
    ? analysis.indicators.map((indicator) => indicator.title).join('; ')
    : 'No configured warning signals were detected.';
  return { ...message, analysis, analysisStatus, analysisNote };
}

export function analyzeMessages(messages) {
  return messages.map(withMessageAnalysis);
}

function collectUrls(message) {
  const fromFields = [message.sender, message.subject, message.body, message.preview]
    .filter((value) => typeof value === 'string')
    .flatMap((value) => value.match(URL_PATTERN) || []);
  const fromMetadata = [message.url, ...(Array.isArray(message.urls) ? message.urls : []), ...(Array.isArray(message.links) ? message.links : [])]
    .map((entry) => typeof entry === 'string' ? entry : entry?.url)
    .filter((value) => typeof value === 'string');
  return [...new Set([...fromFields, ...fromMetadata].map(trimUrl).filter(Boolean))];
}

function trimUrl(value) {
  return value.trim().replace(/[),.!?;:'"\]}]+$/g, '');
}

function inspectUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl.startsWith('www.') ? `https://${rawUrl}` : rawUrl);
  } catch {
    return null;
  }
  const host = parsed.hostname.toLowerCase().replace(/^www\./, '');
  if (!host) return null;
  if (host.includes('xn--')) return { suspicious: true, reason: `The domain “${host}” uses punycode, which can hide look-alike characters.`, weight: 48 };
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return { suspicious: true, reason: `The link points to a raw IP address (${host}) instead of a recognizable domain.`, weight: 48 };
  if (URL_SHORTENERS.has(host)) return { suspicious: true, reason: `The shortened link on ${host} hides its final destination.`, weight: 18 };

  for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
    if (!host.includes(brand)) continue;
    const isOfficialDomain = officialDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
    if (!isOfficialDomain) return { suspicious: true, reason: `The domain “${host}” contains “${brand}” but is not one of its recognized official domains.`, weight: 48 };
  }
  return null;
}

function addIndicator(indicators, code, title, detail, weight) {
  if (!indicators.some((indicator) => indicator.code === code && indicator.detail === detail)) {
    indicators.push({ code, title, detail, weight });
  }
}

function recommendations(indicators) {
  const codes = new Set(indicators.map((indicator) => indicator.code));
  const actions = indicators.length
    ? ['Open the organization’s official app or type its known website yourself to verify the request.']
    : ['No warning signal was found by this limited check. That does not establish that the message is safe; verify unexpected requests through a known, independent channel.'];
  if (codes.has('credential-request') || codes.has('otp-request') || codes.has('personal-info-request')) {
    actions.unshift('Do not send passwords, one-time codes, or personal details in reply to this message.');
  }
  if (codes.has('payment-request') || codes.has('gift-card-payment')) {
    actions.unshift('Do not send money or buy gift cards until you independently confirm who requested it.');
  }
  if (codes.has('suspicious-url') || codes.has('suspicious-link-language')) actions.unshift('Avoid opening the link; check the destination through an official source instead.');
  if (codes.has('urgency')) actions.push('Pause before acting on a deadline or threat in an unexpected message.');
  return [...new Set(actions)];
}
