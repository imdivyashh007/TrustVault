/** Request a safe, metadata-only preview from the authenticated local API. */
export async function requestGmailMetadataPreview({ fetchImpl = fetch, csrfToken }) {
  const response = await fetchImpl('/api/auth/google/sync', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
  });

  let data = {};
  try {
    data = await response.json();
  } catch {
    // Treat an unreadable response as an API failure without surfacing its body.
  }

  if (!response.ok) {
    const error = new Error(safeSyncError(response.status, data));
    error.reconnectRequired = data?.reconnectRequired === true;
    error.unauthenticated = response.status === 401 && !error.reconnectRequired;
    throw error;
  }

  if (!Array.isArray(data?.messages) || data.messages.length > 5) {
    throw new Error('The local API returned an invalid Gmail metadata preview.');
  }

  return data.messages.map((message) => {
    if (!message || typeof message.id !== 'string'
      || typeof message.sender !== 'string'
      || typeof message.subject !== 'string'
      || typeof message.date !== 'string') {
      throw new Error('The local API returned an invalid Gmail metadata preview.');
    }
    // Project only the four fields supported by the metadata-only endpoint.
    return {
      id: message.id,
      sender: message.sender,
      subject: message.subject,
      date: message.date,
    };
  });
}

function safeSyncError(status, data) {
  if (status === 401 && data?.reconnectRequired) {
    return 'Gmail authorization expired or needs reconnecting. Connect Gmail again.';
  }
  if (status === 401) return 'Your TrustVault session expired. Log in again.';
  if (status === 403) return 'The request could not be verified. Refresh TrustVault and try again.';
  if (status === 409) return 'Connect Gmail before requesting a metadata preview.';
  if (status === 429) return 'Gmail preview is temporarily rate limited. Wait briefly and try again.';
  if (status === 503) return 'Local Gmail authorization could not be verified or saved. Reconnect Gmail and try again.';
  if (status === 502) return 'TrustVault could not retrieve Gmail metadata. Try again later.';
  return 'Could not retrieve Gmail metadata. Try again later.';
}

/** Request a local heuristic assessment of one explicitly selected preview item. */
export async function requestGmailMessageAnalysis({ fetchImpl = fetch, csrfToken, messageId }) {
  if (typeof messageId !== 'string' || !/^[A-Za-z0-9_-]{1,512}$/.test(messageId)) {
    throw new Error('Choose a message from the current Gmail preview.');
  }
  const response = await fetchImpl('/api/auth/google/analyze', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ messageId }),
  });
  let data = {};
  try { data = await response.json(); } catch { /* Keep provider details out of the UI. */ }
  if (!response.ok) {
    const error = new Error(safeAnalysisError(response.status, data));
    error.reconnectRequired = data?.reconnectRequired === true;
    error.unauthenticated = response.status === 401 && !error.reconnectRequired;
    throw error;
  }
  const message = data?.message;
  const analysis = data?.analysis;
  if (!message || message.id !== messageId || typeof message.sender !== 'string'
    || typeof message.subject !== 'string' || typeof message.date !== 'string'
    || !analysis || !Number.isInteger(analysis.score) || analysis.score < 0 || analysis.score > 100
    || !['low', 'medium', 'high'].includes(analysis.riskLevel)
    || !Array.isArray(analysis.indicators) || !Array.isArray(analysis.recommendedActions)
    || typeof analysis.explanation !== 'string' || typeof analysis.uncertainty !== 'string') {
    throw new Error('TrustVault returned an invalid Gmail analysis result.');
  }
  return {
    message: { id: message.id, sender: message.sender, subject: message.subject, date: message.date },
    analysis: {
      score: analysis.score,
      riskLevel: analysis.riskLevel,
      indicators: analysis.indicators.filter((item) => item && typeof item.title === 'string' && typeof item.detail === 'string')
        .map(({ code, title, detail }) => ({ code: typeof code === 'string' ? code : 'warning', title, detail })),
      explanation: analysis.explanation,
      uncertainty: analysis.uncertainty,
      recommendedActions: analysis.recommendedActions.filter((item) => typeof item === 'string'),
    },
    notice: typeof data.notice === 'string' ? data.notice : 'This assessment is temporary and was not saved to your vault.',
  };
}

function safeAnalysisError(status, data) {
  if (status === 401 && data?.reconnectRequired) return 'Gmail authorization expired or needs reconnecting. Connect Gmail again.';
  if (status === 401) return 'Your TrustVault session expired. Log in again.';
  if (status === 403) return 'Gmail authorization or request security could not be verified.';
  if (status === 404) return 'That message is no longer in the recent preview. Refresh the preview and try again.';
  if (status === 409) return 'Connect Gmail before analyzing a message.';
  if (status === 422) return 'This message does not meet the supported plain-text, size, or attachment safety checks. No content was analyzed.';
  if (status === 429) return 'Gmail analysis is temporarily rate limited. Wait briefly and try again.';
  if (status === 503) return 'The encrypted Gmail authorization could not be verified or saved. Reconnect Gmail and try again.';
  return 'TrustVault could not safely analyze this Gmail message. Refresh the preview or choose another message.';
}
