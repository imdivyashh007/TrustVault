import { withMessageAnalysis } from './scamAnalysis.js';

const REPORT_DISCLAIMER = 'This score is a local heuristic assessment. It is not a probability and does not prove fraud.';
const DEFAULT_ACTIONS = [
  'Verify unexpected requests using the organization’s official app or website.',
  'Do not share passwords, one-time codes, or personal information in response to an unexpected message.',
];

/** Build a printable report from a stored message and its local content analysis. */
export function generateIncidentReport(message, generatedAt = new Date().toISOString()) {
  if (!message || typeof message !== 'object') return null;

  const analyzedMessage = withMessageAnalysis(message);
  const analysis = analyzedMessage.analysis;
  const indicators = Array.isArray(analysis.indicators) ? analysis.indicators : [];
  const recommendedActions = Array.isArray(analysis.recommendedActions) && analysis.recommendedActions.length
    ? analysis.recommendedActions
    : DEFAULT_ACTIONS;

  return {
    sender: nonEmpty(message.sender, 'Unknown sender'),
    subject: nonEmpty(message.subject, 'No subject'),
    timestamp: nonEmpty(message.timestamp || message.date, 'Date unavailable'),
    source: nonEmpty(message.source, 'Source unavailable'),
    messageText: nonEmpty(message.body || message.preview, 'No message text was provided.'),
    riskScore: Number.isFinite(analysis.score) ? analysis.score : 0,
    riskLevel: nonEmpty(analysis.riskLevel, 'low'),
    indicators: indicators.map(({ code, title, detail }) => ({
      code: nonEmpty(code, 'warning'),
      title: nonEmpty(title, 'Warning signal'),
      explanation: nonEmpty(detail, 'This signal matched a local scam-analysis rule.'),
    })),
    explanation: indicators.length
      ? 'The assessment is based on the warning signals listed below.'
      : 'No configured warning signals were detected in the stored message content.',
    recommendedActions,
    disclaimer: nonEmpty(analysis.disclaimer, REPORT_DISCLAIMER),
    generatedAt,
  };
}

function nonEmpty(value, fallback) {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback;
}
