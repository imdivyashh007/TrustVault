import { useEffect, useMemo, useReducer, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, Bell, Check, ChevronDown, CircleHelp,
  ClipboardList, FileText, Inbox, LayoutDashboard, LockKeyhole, Mail, MoreHorizontal, Plus,
  LogOut, Printer, Search, Settings, ShieldAlert, ShieldCheck, Smartphone, Upload, X,
} from 'lucide-react';
import { previewCsvImport } from './csvImport.js';
import { requestGmailMetadataPreview, requestGmailMessageAnalysis } from './gmailPreview.js';
import { gmailAnalysisReducer, initialGmailAnalysisState } from './gmailAnalysisState.js';

const navItems = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'vault', label: 'My Vault', icon: Inbox },
  { id: 'scam-check', label: 'Scam Check', icon: ShieldCheck },
  { id: 'reports', label: 'Incident Reports', icon: ClipboardList },
  { id: 'gmail', label: 'Connect Gmail', icon: Mail },
  { id: 'activity', label: 'Activity', icon: Activity },
];

const viewTitles = {
  overview: 'Overview',
  vault: 'My Vault',
  'scam-check': 'Scam Check',
  reports: 'Incident Reports',
  gmail: 'Connect Gmail',
  activity: 'Activity',
};

let initialSessionRequest;

function getInitialSession() {
  if (!initialSessionRequest) {
    initialSessionRequest = fetch('/api/auth/session').then(async (response) => {
      if (!response.ok) throw new Error(`The local API returned ${response.status}.`);
      return response.json();
    });
  }
  return initialSessionRequest;
}

function messageStatus(message) {
  if (message.analysis?.riskLevel) return message.analysis.riskLevel;
  if (message.analysisStatus === 'safe') return 'low';
  if (message.analysisStatus === 'review') return 'medium';
  if (message.analysisStatus === 'scam') return 'high';
  return 'unchecked';
}

function statusLabel(status) {
  if (status === 'low') return 'Low risk';
  if (status === 'medium') return 'Medium risk';
  if (status === 'high') return 'High risk';
  return 'Not checked';
}

function App() {
  const [messages, setMessages] = useState([]);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('All messages');
  const [activeView, setActiveView] = useState('overview');
  const [selectedMessage, setSelectedMessage] = useState(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState(null);
  const [importPreview, setImportPreview] = useState(null);
  const [importError, setImportError] = useState('');
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);
  const [reportPreview, setReportPreview] = useState(null);
  const [reportLoadingId, setReportLoadingId] = useState('');
  const [reportError, setReportError] = useState('');
  const [loadState, setLoadState] = useState('loading');
  const [error, setError] = useState('');
  const [authState, setAuthState] = useState('checking');
  const [csrfToken, setCsrfToken] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [authBusy, setAuthBusy] = useState(false);
  const [gmailStatus, setGmailStatus] = useState(null);
  const [gmailStatusLoading, setGmailStatusLoading] = useState(false);
  const [gmailBusy, setGmailBusy] = useState(false);
  const [gmailError, setGmailError] = useState('');
  const [gmailResult, setGmailResult] = useState('');
  const [gmailMessages, setGmailMessages] = useState([]);
  const [gmailPreviewLoaded, setGmailPreviewLoaded] = useState(false);
  const [gmailAnalysis, dispatchGmailAnalysis] = useReducer(gmailAnalysisReducer, initialGmailAnalysisState);
  const gmailCallbackPending = useRef(false);

  async function recoverSession() {
    const session = await fetch('/api/auth/session').then((response) => response.json()).catch(() => null);
    if (session?.csrfToken) setCsrfToken(session.csrfToken);
    setMessages([]);
    dispatchGmailAnalysis({ type: 'clear' });
    setGmailMessages([]);
    setAuthState('login');
  }

  async function loadMessages() {
    setLoadState('loading');
    setError('');
    try {
      const response = await fetch('/api/messages');
      if (response.status === 401) {
        await recoverSession();
        setLoadState('ready');
        return;
      }
      if (!response.ok) throw new Error(`The server returned ${response.status}.`);
      const data = await response.json();
      if (!Array.isArray(data.messages)) throw new Error('The API response did not include a message list.');
      setMessages(data.messages);
      setLoadState('ready');
      if (selectedMessage) {
        setSelectedMessage(data.messages.find((message) => message.id === selectedMessage.id) || null);
      }
    } catch (loadError) {
      setError(loadError.message || 'Could not load the demo messages.');
      setLoadState('error');
    }
  }

  useEffect(() => {
    let active = true;
    getInitialSession()
      .then((session) => {
        if (!active) return;
        setCsrfToken(session.csrfToken || '');
        if (!session.authenticated) {
          setAuthState('login');
          setLoadState('ready');
          return;
        }
        setAuthState('authenticated');
        loadMessages();
      })
      .catch((sessionError) => {
        if (!active) return;
        setAuthError(sessionError.message || 'The local API is unavailable.');
        setAuthState('error');
        setLoadState('error');
      });
    return () => { active = false; };
    // Session is checked once on startup; the cookie is managed by the browser.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const callbackResult = new URLSearchParams(window.location.search).get('gmail');
    const callbackMessages = {
      authorized: 'Google authorization returned. Checking the local encrypted token store…',
      'save-failed': 'Google authorization returned, but TrustVault could not verify the saved encrypted token bundle. Gmail is not connected. Check the local token store before retrying.',
      cancelled: 'Google authorization was cancelled. No Gmail data was fetched or saved.',
      failed: 'Google authorization could not be completed. Check the local configuration and try again.',
      'not-configured': 'Gmail OAuth is not configured on this local backend.',
      expired: 'The local sign-in expired during authorization. Log in again before reconnecting.',
    };
    if (callbackResult && callbackMessages[callbackResult]) {
      setActiveView('gmail');
      gmailCallbackPending.current = callbackResult === 'authorized';
      setGmailResult(callbackMessages[callbackResult]);
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  useEffect(() => {
    if (activeView !== 'gmail' || authState !== 'authenticated') return undefined;
    let active = true;
    setGmailStatusLoading(true);
    setGmailError('');
    fetch('/api/auth/google/status')
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || `The server returned ${response.status}.`);
        return data;
      })
      .then((data) => {
        if (!active) return;
        setGmailStatus(data);
        if (gmailCallbackPending.current) {
          gmailCallbackPending.current = false;
          setGmailResult(data.connected
            ? 'Google authorization completed and its token bundle is encrypted in the local store. No Gmail messages have been fetched.'
            : 'Google authorization returned, but no readable encrypted token bundle is available locally. Gmail is not connected; try connecting again.');
        }
      })
      .catch((statusError) => {
        if (!active) return;
        setGmailError(statusError.message || 'Could not check Gmail setup.');
        if (gmailCallbackPending.current) {
          gmailCallbackPending.current = false;
          setGmailResult('TrustVault could not verify the local token store, so Gmail is not shown as connected.');
        }
      })
      .finally(() => { if (active) setGmailStatusLoading(false); });
    return () => { active = false; };
  }, [activeView, authState]);

  async function submitLogin(event) {
    event.preventDefault();
    setAuthBusy(true);
    setAuthError('');
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ password }),
      });
      const result = await response.json();
      if (response.status === 401 || response.status === 403) await recoverSession();
      if (!response.ok) throw new Error(result.error || 'Login failed.');
      setCsrfToken(result.csrfToken || '');
      setPassword('');
      setAuthState('authenticated');
      setLoadState('loading');
      await loadMessages();
    } catch (loginError) {
      setAuthError(loginError.message || 'Could not log in to the local vault.');
    } finally {
      setAuthBusy(false);
    }
  }

  async function logout() {
    setAuthError('');
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken },
      });
      const result = await response.json();
      if (response.status === 401) await recoverSession();
      if (!response.ok) throw new Error(result.error || 'Logout failed.');
      setMessages([]);
      setSelectedMessage(null);
      setGmailMessages([]);
      setGmailPreviewLoaded(false);
      dispatchGmailAnalysis({ type: 'clear' });
      setCsrfToken(result.csrfToken || '');
      setAuthState('login');
      setLoadState('ready');
    } catch (logoutError) {
      setAuthError(logoutError.message || 'Could not log out.');
    }
  }

  async function startGmailAuthorization() {
    setGmailBusy(true);
    setGmailError('');
    setGmailResult('');
    try {
      const response = await fetch('/api/auth/google/start', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken },
      });
      const data = await response.json();
      if (response.status === 401) await recoverSession();
      if (!response.ok) throw new Error(data.error || `The server returned ${response.status}.`);
      if (typeof data.authorizationUrl !== 'string') throw new Error('The local API did not return a Google authorization URL.');
      window.location.assign(data.authorizationUrl);
    } catch (requestError) {
      setGmailError(requestError.message || 'Could not start Google authorization.');
      setGmailBusy(false);
    }
  }

  async function disconnectGmail() {
    setGmailBusy(true);
    setGmailError('');
    setGmailResult('');
    try {
      const response = await fetch('/api/auth/google/disconnect', {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': csrfToken },
      });
      const data = await response.json();
      if (response.status === 401) await recoverSession();
      if (!response.ok) throw new Error(data.error || `The server returned ${response.status}.`);
      setGmailResult(data.message);
      setGmailMessages([]);
      setGmailPreviewLoaded(false);
      dispatchGmailAnalysis({ type: 'clear' });
      const statusResponse = await fetch('/api/auth/google/status');
      const status = await statusResponse.json();
      if (!statusResponse.ok) throw new Error(status.error || 'Could not refresh Gmail connection status.');
      setGmailStatus(status);
    } catch (disconnectError) {
      setGmailError(disconnectError.message || 'Could not remove the local Gmail token bundle.');
    } finally {
      setGmailBusy(false);
    }
  }

  async function previewGmailMetadata() {
    setGmailBusy(true);
    setGmailError('');
    setGmailResult('');
    setGmailMessages([]);
    setGmailPreviewLoaded(false);
    dispatchGmailAnalysis({ type: 'clear' });
    try {
      const preview = await requestGmailMetadataPreview({ csrfToken });
      setGmailMessages(preview);
      setGmailPreviewLoaded(true);
    } catch (syncError) {
      if (syncError.unauthenticated) await recoverSession();
      if (syncError.reconnectRequired) setGmailStatus((current) => current ? { ...current, connected: false } : current);
      setGmailError(syncError.message || 'Could not retrieve Gmail metadata.');
    } finally {
      setGmailBusy(false);
    }
  }

  async function analyzeGmailMessage(message) {
    dispatchGmailAnalysis({ type: 'start', message });
    try {
      const result = await requestGmailMessageAnalysis({ csrfToken, messageId: message.id });
      dispatchGmailAnalysis({ type: 'success', result });
    } catch (analysisError) {
      if (analysisError.unauthenticated) await recoverSession();
      if (analysisError.reconnectRequired) setGmailStatus((current) => current ? { ...current, connected: false } : current);
      dispatchGmailAnalysis({ type: 'failure', message: analysisError.message || 'TrustVault could not safely analyze this message.' });
    }
  }

  const visibleMessages = useMemo(() => {
    let result = messages;
    if (activeView === 'scam-check') result = result.filter((message) => ['medium', 'high'].includes(messageStatus(message)));
    if (typeFilter !== 'All messages') result = result.filter((message) => message.type === typeFilter);
    const search = query.trim().toLowerCase();
    if (search) {
      result = result.filter((message) =>
        `${message.sender || ''} ${message.subject || ''} ${message.body || ''}`.toLowerCase().includes(search),
      );
    }
    return result;
  }, [messages, activeView, typeFilter, query]);

  const counts = useMemo(() => ({
    saved: messages.length,
    review: messages.filter((message) => ['medium', 'high'].includes(messageStatus(message))).length,
    checked: messages.filter((message) => Boolean(message.analysis)).length,
  }), [messages]);

  function openView(view) {
    if (view !== 'gmail') dispatchGmailAnalysis({ type: 'clear' });
    setSelectedMessage(null);
    setActiveView(view);
    setQuery('');
    setTypeFilter('All messages');
    setReportPreview(null);
    setReportError('');
  }

  async function generateIncidentReport(messageId) {
    setSelectedMessage(null);
    setActiveView('reports');
    setQuery('');
    setTypeFilter('All messages');
    setReportPreview(null);
    setReportError('');
    setReportLoadingId(messageId);
    try {
      const response = await fetch(`/api/messages/${encodeURIComponent(messageId)}/report`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } });
      const data = await response.json();
      if (response.status === 401) await recoverSession();
      if (!response.ok) throw new Error(data.error || `The server returned ${response.status}.`);
      if (!data.report) throw new Error('The API did not return a report.');
      setReportPreview(data.report);
    } catch (requestError) {
      setReportError(requestError.message || 'The report could not be generated. Check the local API and try again.');
    } finally {
      setReportLoadingId('');
    }
  }

  function openImportDialog() {
    setImportFile(null);
    setImportPreview(null);
    setImportError('');
    setImportResult(null);
    setImportOpen(true);
  }

  async function handleFileSelection(event) {
    const file = event.target.files?.[0];
    setImportFile(null);
    setImportPreview(null);
    setImportError('');
    setImportResult(null);
    if (!file) return;
    const fileType = file.type.toLowerCase().split(';')[0].trim();
    const allowedTypes = ['', 'text/csv', 'application/csv', 'application/vnd.ms-excel'];
    if (!file.name.toLowerCase().endsWith('.csv') || !allowedTypes.includes(fileType)) {
      setImportError('Choose a CSV file (.csv). The selected file type is not supported.');
      event.target.value = '';
      return;
    }
    setImportFile(file);
    try {
      const text = await file.text();
      setImportPreview(previewCsvImport(text, file.size));
    } catch {
      setImportError('The selected file could not be read. Try choosing it again.');
    }
  }

  async function submitImport() {
    if (!importFile || !importPreview || importPreview.fileError || !importPreview.rows.some((row) => row.valid)) return;
    setImporting(true);
    setImportError('');
    try {
      const csv = await importFile.text();
      const response = await fetch('/api/messages/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ filename: importFile.name, csv }),
      });
      const result = await response.json();
      if (response.status === 401) await recoverSession();
      if (!response.ok) throw new Error(result.error || result.errors?.join(' ') || 'The import could not be completed.');
      await loadMessages();
      setImportResult(result);
    } catch (submitError) {
      setImportError(submitError.message || 'The import could not be completed. Check the local API and try again.');
    } finally {
      setImporting(false);
    }
  }

  function renderLoadState() {
    if (loadState === 'loading') {
      return <div className="state-panel" role="status"><span className="loading-spinner" /><strong>Loading your demo messages…</strong><p>Connecting to the local TrustVault API.</p></div>;
    }
    if (loadState === 'error') {
      return <div className="state-panel error-panel" role="alert"><div className="state-icon error-icon"><AlertTriangle size={19} /></div><strong>We couldn’t load your messages.</strong><p>{error} Check that the Express server is running, then try again.</p><button className="secondary-button" onClick={loadMessages}>Try again</button></div>;
    }
    if (messages.length === 0) {
      return <div className="empty-state"><div className="empty-art"><div className="art-orbit orbit-one" /><div className="art-orbit orbit-two" /><div className="art-glow" /><div className="art-card back-card"><span /><span /><span /></div><div className="art-card front-card"><div className="art-lock"><LockKeyhole size={23} /></div><span /><span /><span /></div><div className="art-spark spark-two"><Check size={13} /></div></div><h3>Your vault is a blank slate.</h3><p>No messages are stored in the local API yet. Import a fictional or user-authorized CSV record to get started.</p><button className="empty-cta" onClick={openImportDialog}><Plus size={16} /> Add to your vault</button><div className="empty-note"><LockKeyhole size={12} /> Imported messages stay in this app’s local data store</div></div>;
    }
    if (visibleMessages.length === 0) {
      return <div className="state-panel no-results"><Search size={19} /><strong>No messages match these filters.</strong><p>Try another search or choose a different message type.</p><button className="secondary-button" onClick={() => { setQuery(''); setTypeFilter('All messages'); }}>Clear filters</button></div>;
    }
    return <div className="message-list">{visibleMessages.map((message) => <button className="message-row" key={message.id} onClick={() => setSelectedMessage(message)}><span className={`message-type ${message.type === 'SMS' ? 'type-sms' : 'type-email'}`}>{message.type === 'SMS' ? <Smartphone size={17} /> : <Mail size={17} />}</span><span className="message-copy"><span className="message-title-row"><strong>{message.sender}</strong><span className="message-date">{message.date}</span></span><span className="message-subject">{message.subject}</span><span className="message-preview">{message.preview || message.body}</span></span><span className={`status-pill status-${messageStatus(message)}`}>{messageStatus(message) === 'low' ? <ShieldCheck size={13} /> : <AlertTriangle size={13} />}{statusLabel(messageStatus(message))}</span><ArrowRight className="message-arrow" size={15} /></button>)}</div>;
  }

  function renderDetail() {
    const message = selectedMessage;
    const status = messageStatus(message);
    const analysis = message.analysis || { score: 0, indicators: [], recommendedActions: [], disclaimer: 'Analysis details are unavailable.' };
    return <section className="detail-panel"><div className="detail-actions"><button className="back-button" onClick={() => setSelectedMessage(null)}><ArrowRight size={15} /> Back to {viewTitles[activeView]}</button><button className="secondary-button" onClick={() => generateIncidentReport(message.id)}><ClipboardList size={14} /> Generate incident report</button></div><div className="detail-header"><div className={`message-type large ${message.type === 'SMS' ? 'type-sms' : 'type-email'}`}>{message.type === 'SMS' ? <Smartphone size={20} /> : <Mail size={20} />}</div><div><div className="detail-kicker">{message.type} MESSAGE</div><h2>{message.sender}</h2></div><span className={`status-pill status-${status}`}>{status === 'low' ? <ShieldCheck size={13} /> : <AlertTriangle size={13} />}{statusLabel(status)}</span></div><div className="detail-fields"><div><span>DATE</span><strong>{message.date}</strong></div><div><span>SOURCE</span><strong>{message.source || `Fictional ${message.type} sample`}</strong></div><div className="detail-subject"><span>SUBJECT</span><strong>{message.subject || 'No subject'}</strong></div></div><div className="detail-body"><div className="detail-body-heading"><FileText size={15} /> Full message</div><p>{message.body || message.preview || 'No message body was provided.'}</p></div><section className={`analysis-results analysis-${status}`} aria-label="Scam analysis"><div className="analysis-heading"><div><div className="detail-kicker">LOCAL HEURISTIC ASSESSMENT</div><h3>{statusLabel(status)}</h3></div><div className="analysis-score"><strong>{analysis.score}</strong><span>heuristic points / 100</span></div></div><p className="analysis-disclaimer">{analysis.disclaimer}</p><div className="analysis-list-heading">Why this assessment</div>{analysis.indicators.length ? <ul className="analysis-indicators">{analysis.indicators.map((indicator) => <li key={indicator.code}><strong>{indicator.title}</strong><span>{indicator.detail}</span></li>)}</ul> : <p className="analysis-no-signals">No configured warning signals were detected. Still verify unexpected requests independently.</p>}<div className="analysis-list-heading">Safer next steps</div><ul className="analysis-actions">{analysis.recommendedActions.map((action) => <li key={action}>{action}</li>)}</ul></section></section>;
  }

  function renderActivity() {
    return <div className="activity-list">{visibleMessages.map((message) => <div className="activity-row" key={message.id}><span className={`activity-marker marker-${messageStatus(message)}`}><ShieldCheck size={14} /></span><div><strong>{['medium', 'high'].includes(messageStatus(message)) ? `${statusLabel(messageStatus(message))} — review suggested` : 'Low heuristic risk'}</strong><p><b>{message.sender}</b> · {message.subject}</p><span>{message.date} · Local analysis</span></div><button aria-label={`View ${message.sender} message`} onClick={() => setSelectedMessage(message)}><ArrowRight size={15} /></button></div>)}</div>;
  }

  function renderReports() {
    if (loadState !== 'ready') return renderLoadState();
    if (messages.length === 0) {
      return <div className="state-panel"><ClipboardList size={22} /><strong>No messages are available for a report.</strong><p>Import a fictional or user-authorized CSV record to create an incident report.</p><button className="secondary-button" onClick={openImportDialog}>Add to your vault</button></div>;
    }
    if (reportPreview) {
      const generatedAt = new Date(reportPreview.generatedAt);
      const generatedLabel = Number.isNaN(generatedAt.getTime()) ? reportPreview.generatedAt : generatedAt.toLocaleString();
      return <>
        <div className="report-toolbar">
          <button className="secondary-button" onClick={() => { setReportPreview(null); setReportError(''); }}>Choose another message</button>
          <button className="primary-button" onClick={() => window.print()}><Printer size={15} /> Print / Save as PDF</button>
        </div>
        <article className="incident-report-preview" aria-label="Incident report preview">
          <header className="report-header"><div className="report-brand"><span className="brand-mark"><ShieldCheck size={18} /></span><span>TrustVault <small>INCIDENT REPORT</small></span></div><div className="report-generated"><span>REPORT GENERATED</span><strong>{generatedLabel}</strong></div></header>
          <div className="report-title-row"><div><div className="detail-kicker">MESSAGE REVIEW</div><h2>Incident report</h2><p>Prepared from a message stored in your local TrustVault vault.</p></div><span className={`status-pill status-${reportPreview.riskLevel}`}>{statusLabel(reportPreview.riskLevel)}</span></div>
          <section className="report-section"><h3>Message details</h3><dl className="report-fields"><div><dt>Sender</dt><dd>{reportPreview.sender}</dd></div><div><dt>Subject</dt><dd>{reportPreview.subject}</dd></div><div><dt>Timestamp</dt><dd>{reportPreview.timestamp}</dd></div><div><dt>Source</dt><dd>{reportPreview.source}</dd></div></dl></section>
          <section className="report-section"><h3>Message text</h3><p className="report-message-text">{reportPreview.messageText}</p></section>
          <section className="report-section"><h3>Scam analysis</h3><div className="report-risk"><strong>{reportPreview.riskScore}</strong><span>heuristic points / 100</span><b>{statusLabel(reportPreview.riskLevel)}</b></div><p className="report-disclaimer">{reportPreview.disclaimer}</p><p className="report-explanation">{reportPreview.explanation}</p>{reportPreview.indicators.length ? <ul className="report-indicators">{reportPreview.indicators.map((indicator) => <li key={indicator.code}><strong>{indicator.title}</strong><span>{indicator.explanation}</span></li>)}</ul> : <p className="report-no-indicators">No configured warning indicators were found.</p>}</section>
          <section className="report-section"><h3>Recommended safe actions</h3><ul className="report-actions">{reportPreview.recommendedActions.map((action) => <li key={action}>{action}</li>)}</ul></section>
          <footer className="report-footer">Generated locally by TrustVault · Message content was not sent to an external service.</footer>
        </article>
      </>;
    }
    return <div className="report-selector">
      <div className="report-selector-intro"><ClipboardList size={17} /><div><strong>Select a message to report</strong><span>Choose a saved message. TrustVault creates the report from its stored text and local scam analysis.</span></div></div>
      {reportError && <div className="import-error" role="alert">{reportError}</div>}
      <div className="report-message-list">{messages.map((message) => <div className="report-message-row" key={message.id}><span className={`message-type ${message.type === 'SMS' ? 'type-sms' : 'type-email'}`}>{message.type === 'SMS' ? <Smartphone size={16} /> : <Mail size={16} />}</span><div className="report-message-copy"><strong>{message.sender || 'Unknown sender'}</strong><span>{message.subject || 'No subject'} · {message.date || message.timestamp || 'Date unavailable'}</span></div><span className={`status-pill status-${messageStatus(message)}`}>{statusLabel(messageStatus(message))}</span><button className="secondary-button" disabled={reportLoadingId === message.id} onClick={() => generateIncidentReport(message.id)}>{reportLoadingId === message.id ? 'Generating…' : 'Generate report'}</button></div>)}</div>
    </div>;
  }

  function renderGmail() {
    return <div className="state-panel gmail-connect-panel">
      <span className="brand-mark"><Mail size={20} /></span>
      <strong>{gmailStatus?.connected ? 'Gmail is connected' : 'Connect a Gmail account'}</strong>
      <p>TrustVault uses Gmail read-only access. It will not send, modify, or delete email. Message content is fetched only after you choose a preview item and confirm the analysis action below.</p>
      {gmailStatusLoading && <p role="status">Checking local OAuth configuration…</p>}
      {gmailStatus && <p role="status">{gmailStatus.connected ? 'Gmail read-only authorization is saved in the encrypted local token store.' : gmailStatus.enabled ? 'OAuth credentials and encrypted token storage are configured. Connect Gmail to save an authorization.' : gmailStatus.message}</p>}
      {gmailError && <div className="import-error" role="alert">{gmailError}</div>}
      {gmailResult && <div className="dialog-demo-note" role="status">{gmailResult}</div>}
      {gmailStatus?.connected
        ? <button className="secondary-button" disabled={gmailBusy || gmailStatusLoading} onClick={disconnectGmail}>{gmailBusy ? 'Removing…' : 'Disconnect locally'}</button>
        : <button className="primary-button" disabled={gmailBusy || gmailStatusLoading || !gmailStatus?.enabled} onClick={startGmailAuthorization}>
          <Mail size={15} /> {gmailBusy ? 'Opening Google…' : 'Continue with Google'}
        </button>}
      {gmailAnalysis.error && <div className="import-error" role="alert">{gmailAnalysis.error}</div>}
      <section className="gmail-metadata-preview" aria-label="Gmail metadata preview">
        <div className="gmail-preview-heading"><div><strong>Gmail metadata preview</strong><span>At most the 5 newest messages · From, Subject, and Date headers only.</span></div><button className="primary-button" disabled={gmailBusy || gmailStatusLoading || !gmailStatus?.connected} onClick={previewGmailMetadata}>{gmailBusy ? 'Loading Gmail metadata…' : 'Preview recent Gmail messages'}</button></div>
        <p className="gmail-preview-notice">The metadata preview retrieves only message IDs and these headers. Bodies are requested only after you choose one message and confirm analysis. Preview and analysis results stay separate from your vault and Scam Check queue.</p>
        {!gmailStatus?.connected && <p className="gmail-preview-empty" role="status">Connect Gmail above to enable the metadata preview.</p>}
        {gmailPreviewLoaded && gmailMessages.length > 0 && <p className="gmail-preview-empty" role="status">Metadata preview loaded: {gmailMessages.length} {gmailMessages.length === 1 ? 'message' : 'messages'}. Message content was not fetched.</p>}
        {gmailPreviewLoaded && gmailMessages.length === 0 && <div className="gmail-preview-empty" role="status">No message metadata was returned.</div>}
        {gmailMessages.length > 0 && <div className="gmail-preview-list">{gmailMessages.map((message) => <article className="gmail-preview-row" key={message.id}><div><span>FROM</span><strong>{message.sender}</strong></div><div><span>SUBJECT</span><strong>{message.subject}</strong></div><div><span>DATE</span><strong>{message.date}</strong></div><button className="secondary-button gmail-analyze-button" disabled={gmailAnalysis.busy || gmailBusy} onClick={() => dispatchGmailAnalysis({ type: 'confirm', message })}>{gmailAnalysis.busy && gmailAnalysis.target?.id === message.id ? 'Analyzing…' : 'Analyze this email'}</button></article>)}</div>}
        {gmailAnalysis.result && <section className="gmail-analysis-result" aria-label="Temporary Gmail scam assessment"><div className="gmail-analysis-heading"><div><span>LOCAL HEURISTIC ASSESSMENT</span><h3>{gmailAnalysis.result.message.subject || '(no subject)'}</h3><p>{gmailAnalysis.result.message.sender} · {gmailAnalysis.result.message.date}</p></div><span className={`gmail-risk-pill risk-${gmailAnalysis.result.analysis.riskLevel}`}>{gmailAnalysis.result.analysis.riskLevel} risk · {gmailAnalysis.result.analysis.score}/100</span></div><p className="gmail-analysis-disclaimer">This score is heuristic, not a probability or proof of fraud. {gmailAnalysis.result.analysis.uncertainty}</p><section><strong>Why this assessment</strong><p>{gmailAnalysis.result.analysis.explanation}</p>{gmailAnalysis.result.analysis.indicators.length > 0 ? <ul>{gmailAnalysis.result.analysis.indicators.map((indicator, index) => <li key={`${indicator.code}-${index}`}><b>{indicator.title}</b><span>{indicator.detail}</span></li>)}</ul> : <p>No configured warning indicators were detected in the supported plain-text content.</p>}</section><section><strong>Safe next steps</strong><ul>{gmailAnalysis.result.analysis.recommendedActions.map((action) => <li key={action}>{action}</li>)}</ul></section><div className="gmail-analysis-notice">{gmailAnalysis.result.notice} This result is temporary and separate from your vault and Scam Check queue.</div><button className="text-button" onClick={() => dispatchGmailAnalysis({ type: 'clear' })}>Clear temporary result</button></section>}
      </section>
      <div className="auth-footnote"><LockKeyhole size={13} /> Local token removal does not revoke Google authorization. Gmail analysis is temporary and is not added to the vault.</div>
    </div>;
  }

  const pageTitle = selectedMessage ? 'Message details' : viewTitles[activeView];
  const viewDescription = {
    overview: 'Important messages, kept safe and easy to find.',
    vault: 'Browse your saved fictional SMS and email samples.',
    'scam-check': 'Review messages marked for closer attention.',
    reports: 'Prepare a local, printable summary of a saved message and its analysis.',
    gmail: 'Preview at most five recent Gmail messages. Analyze a supported message only after explicit confirmation.',
    activity: 'A simple history of the messages checked in this demo.',
  }[activeView];

  if (authState === 'checking') {
    return <div className="auth-screen"><div className="auth-card"><div className="brand-mark"><ShieldCheck size={21} /></div><strong>Checking your local session…</strong></div></div>;
  }

  if (authState === 'error') {
    return <div className="auth-screen"><section className="auth-card" role="alert"><div className="brand-mark"><ShieldCheck size={21} /></div><h1>TrustVault is unavailable</h1><p>{authError}</p><p>Start the local backend after configuring authentication with <code>npm run setup-auth</code> from the backend folder.</p><button className="primary-button" onClick={() => window.location.reload()}>Try again</button></section></div>;
  }

  if (authState === 'login') {
    return <div className="auth-screen"><section className="auth-card"><div className="brand-mark"><ShieldCheck size={21} /></div><div className="section-kicker">LOCAL SINGLE-USER VAULT</div><h1>Welcome to TrustVault</h1><p>Enter your local password to open this vault on this Mac.</p><form onSubmit={submitLogin}><label htmlFor="trustvault-password">Password</label><input id="trustvault-password" type="password" autoComplete="current-password" minLength={12} maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} required /><button className="primary-button" disabled={authBusy || !csrfToken}>{authBusy ? 'Signing in…' : 'Log in'} <ArrowRight size={15} /></button></form>{authError && <div className="import-error" role="alert">{authError}</div>}<div className="auth-footnote"><LockKeyhole size={13} /> Session data stays in local backend memory and expires after eight hours.</div></section></div>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#home" aria-label="TrustVault home" onClick={(event) => { event.preventDefault(); openView('overview'); }}><span className="brand-mark"><ShieldCheck size={21} strokeWidth={2.4} /></span><span className="brand-name">trust<span>vault</span></span></a>
        <div className="workspace-switcher"><div className="workspace-avatar">S</div><div className="workspace-copy"><strong>Student workspace</strong><span>Free plan</span></div><ChevronDown size={15} className="muted-icon" /></div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">{navItems.map(({ id, label, icon: Icon }) => <button className={`nav-item${activeView === id && !selectedMessage ? ' active' : ''}`} onClick={() => openView(id)} key={id}><Icon size={18} strokeWidth={1.9} /><span>{label}</span>{id === 'vault' && <span className="nav-count">{loadState === 'ready' ? counts.saved : '—'}</span>}{id === 'scam-check' && <span className="nav-count">{loadState === 'ready' ? counts.review : '—'}</span>}</button>)}</nav>
        <div className="nav-label tools-label">SAMPLE SOURCES</div><div className="connection-item"><span className="connection-icon sms"><Smartphone size={16} /></span><span>SMS via CSV</span><span className="connection-dot" /></div><div className="connection-item"><span className="connection-icon email"><Mail size={16} /></span><span>Email via CSV</span><span className="connection-dot" /></div>
        <div className="sidebar-spacer" /><div className="storage-card"><div className="storage-top"><span className="storage-icon"><LockKeyhole size={15} /></span><span>Vault storage</span><span className="storage-value">{loadState === 'ready' ? `${Math.min(counts.saved * 2, 100)}%` : '—'}</span></div><div className="progress-track"><div style={{ width: `${Math.min(counts.saved * 2, 100)}%` }} /></div><p>{loadState === 'ready' ? `${counts.saved} fictional records loaded.` : 'Waiting for the vault to load.'}</p></div>
        <button className="nav-item bottom-link" onClick={openImportDialog}><Settings size={18} /><span>Import options</span></button><button className="nav-item bottom-link" onClick={openImportDialog}><CircleHelp size={18} /><span>Help & support</span></button><div className="profile-row"><div className="profile-avatar">JD</div><div className="profile-copy"><strong>Demo workspace</strong><span>Fictional records only</span></div><MoreHorizontal size={19} className="muted-icon" /></div>
      </aside>

      <main className="main-content">
        <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>{pageTitle}</strong></div><div className="topbar-actions"><div className={`secure-indicator connection-${loadState}`}><span className="secure-dot" />{loadState === 'ready' ? 'API connected' : loadState === 'loading' ? 'Connecting…' : 'API unavailable'}</div><button className="icon-button notification-button" aria-label="Notifications"><Bell size={18} /><i /></button><button className="logout-button" onClick={logout}><LogOut size={14} /> Log out</button><div className="topbar-avatar">TV</div></div></header>
        <div className="page-content">
          {!selectedMessage && <section className="welcome-row"><div><div className="eyebrow"><span className="eyebrow-line" />YOUR PERSONAL SECURITY HUB</div><h1>{activeView === 'overview' ? <>Your communications,<br className="mobile-break" /> <span>in safe hands.</span></> : <span>{pageTitle}</span>}</h1><p className="welcome-subtitle">{activeView === 'overview' ? 'A little more peace of mind, every time you open your inbox.' : viewDescription}</p></div><button className="primary-button" onClick={openImportDialog}><Plus size={17} strokeWidth={2.5} /> Add to your vault</button></section>}

          {activeView === 'overview' && !selectedMessage && <section className="stats-grid" aria-label="Vault summary"><div className="stat-card"><div className="stat-top"><span className="stat-label">IN YOUR VAULT</span><span className="stat-icon purple"><Inbox size={17} /></span></div><div className="stat-main"><strong>{loadState === 'ready' ? counts.saved : '—'}</strong><span className="stat-trend neutral">Fictional records</span></div><div className="stat-foot">Messages loaded from the API</div><div className="stat-sparkline spark-purple"><i /><i /><i /><i /><i /><i /><i /><i /><i /></div></div><div className="stat-card"><div className="stat-top"><span className="stat-label">FLAGGED FOR REVIEW</span><span className="stat-icon green"><ShieldAlert size={17} /></span></div><div className="stat-main"><strong>{loadState === 'ready' ? counts.review : '—'}</strong><span className="stat-trend neutral">Needs a closer look</span></div><div className="stat-foot">Not a confirmed scam count</div><div className="stat-sparkline spark-green"><i /><i /><i /><i /><i /><i /><i /><i /><i /></div></div><div className="stat-card"><div className="stat-top"><span className="stat-label">MESSAGES CHECKED</span><span className="stat-icon amber"><Activity size={17} /></span></div><div className="stat-main"><strong>{loadState === 'ready' ? counts.checked : '—'}</strong><span className="stat-trend neutral">Analysis status recorded</span></div><div className="stat-foot">Counts low, medium, or high risk assessments</div><div className="stat-sparkline spark-amber"><i /><i /><i /><i /><i /><i /><i /><i /><i /></div></div></section>}

          <section className={`vault-section${['reports', 'gmail'].includes(activeView) ? ' reports-section' : ''}`}><div className="section-heading"><div><div className="section-kicker"><span className="section-kicker-icon"><LockKeyhole size={13} /></span>{activeView === 'scam-check' ? 'REVIEW QUEUE' : activeView === 'activity' ? 'RECENT EVENTS' : activeView === 'reports' ? 'INCIDENT REPORTS' : activeView === 'gmail' ? 'LOCAL AUTHORIZATION' : 'YOUR PRIVATE SPACE'}</div><h2>{selectedMessage ? 'Message details' : activeView === 'overview' ? 'Your communication vault' : activeView === 'vault' ? 'Saved messages' : activeView === 'scam-check' ? 'Messages to review' : activeView === 'reports' ? reportPreview ? 'Incident report preview' : 'Generate a report' : activeView === 'gmail' ? 'Read-only Gmail access' : 'Recent activity'}</h2><p>{selectedMessage ? 'Review the source and full content of this record.' : activeView === 'reports' ? reportPreview ? 'Review the message details and local assessment before printing.' : viewDescription : viewDescription}</p></div>{selectedMessage ? <button className="text-button" onClick={() => setSelectedMessage(null)}>Back to list <ArrowRight size={15} /></button> : !['activity', 'gmail'].includes(activeView) && <button className="text-button" onClick={() => openView('vault')}>View vault <ArrowRight size={15} /></button>}</div>
            {!selectedMessage && !['activity', 'reports', 'gmail'].includes(activeView) && <div className="vault-toolbar"><label className="search-box"><Search size={17} /><input id="vault-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by sender, subject, or body..." aria-label="Search by sender, subject, or body" /><kbd>⌘ K</kbd></label><label className="filter-label"><span className="visually-hidden">Filter message type</span><select className="filter-button" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}><option>All messages</option><option>SMS</option><option>Email</option></select><ChevronDown className="select-chevron" size={14} /></label><button className="filter-icon" aria-label="Refresh messages" onClick={loadMessages}><Activity size={16} /></button></div>}
            {selectedMessage ? renderDetail() : activeView === 'reports' ? renderReports() : activeView === 'gmail' ? renderGmail() : activeView === 'activity' && loadState === 'ready' ? messages.length ? renderActivity() : renderLoadState() : renderLoadState()}
            {loadState === 'ready' && !['reports', 'gmail'].includes(activeView) && <div className="demo-note"><span className="demo-dot" /><span>Fictional sample messages for preview</span><span className="demo-separator">·</span><span>Gmail preview stays separate</span><FileText size={13} /></div>}
          </section>

          {activeView === 'overview' && !selectedMessage && <section className="bottom-grid"><div className="tip-card"><div className="tip-icon"><ShieldCheck size={17} /></div><div className="tip-copy"><div className="tip-label">A QUICK SAFETY TIP <span>DEMO</span></div><strong>Pause before you tap.</strong><p>Unexpected messages asking for personal info or urgent action deserve a closer look.</p></div><span className="tip-next"><ArrowRight size={16} /></span></div><div className="help-card"><div className="help-icon"><CircleHelp size={17} /></div><div className="help-copy"><strong>Bring in your messages</strong><p>Preview fictional or user-authorized CSV records before saving.</p></div><button aria-label="Open CSV import" onClick={openImportDialog}><ArrowRight size={16} /></button></div></section>}
          <footer className="footer"><span>© 2026 TrustVault</span><span><span className="footer-lock"><LockKeyhole size={11} /></span> Built with your privacy in mind</span><a href="#privacy" onClick={(event) => event.preventDefault()}>Privacy</a><a href="#terms" onClick={(event) => event.preventDefault()}>Terms</a></footer>
        </div>
      </main>

      {gmailAnalysis.target && <div className="dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !gmailAnalysis.busy) dispatchGmailAnalysis({ type: 'cancel' }); }}><section className="import-dialog gmail-consent-dialog" role="dialog" aria-modal="true" aria-labelledby="gmail-analysis-consent-title"><button className="dialog-close" aria-label="Cancel analysis" disabled={gmailAnalysis.busy} onClick={() => dispatchGmailAnalysis({ type: 'cancel' })}><X size={18} /></button><div className="dialog-icon"><ShieldCheck size={20} /></div><div className="section-kicker">ONE MESSAGE · LOCAL ANALYSIS</div><h2 id="gmail-analysis-consent-title">Analyze this selected email?</h2><p><strong>{gmailAnalysis.target.subject || '(no subject)'}</strong><br />From {gmailAnalysis.target.sender}</p><div className="gmail-consent-details"><p>After you choose <b>Analyze selected email</b>, TrustVault will re-check that this message is among the five recent preview items and inspect MIME structure without body data. It supports a single <code>text/plain</code> body or a simple two-part <code>multipart/alternative</code> containing one plain-text part and one HTML alternative. For multipart messages, Gmail returns both alternatives to the local backend; TrustVault passes only the plain-text part to the analyzer. The combined alternatives must be at most 64 KB.</p><p>TrustVault rejects attachments, nested or unsupported MIME structures, malformed content, and oversized alternatives. HTML is not interpreted, displayed, or analyzed. No snippets or attachments are requested, and the selected text is not sent to an external AI service or saved to the vault.</p><p>Sender, subject, and date alone cannot reliably identify scams. The result is uncertain heuristic guidance, not proof of fraud.</p></div>{gmailAnalysis.error && <div className="import-error" role="alert">{gmailAnalysis.error}</div>}<div className="dialog-actions"><button className="secondary-button" disabled={gmailAnalysis.busy} onClick={() => dispatchGmailAnalysis({ type: 'cancel' })}>Cancel</button><button className="primary-button" disabled={gmailAnalysis.busy} onClick={() => analyzeGmailMessage(gmailAnalysis.target)}>{gmailAnalysis.busy ? 'Analyzing selected email…' : 'Analyze selected email'} <ArrowRight size={15} /></button></div></section></div>}

      {importOpen && <div className="dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !importing) setImportOpen(false); }}><section className="import-dialog import-workflow" role="dialog" aria-modal="true" aria-labelledby="import-title"><button className="dialog-close" aria-label="Close dialog" disabled={importing} onClick={() => setImportOpen(false)}><X size={18} /></button>{importResult ? <><div className="dialog-icon"><Check size={20} /></div><div className="section-kicker">IMPORT COMPLETE</div><h2 id="import-title">Your vault is up to date</h2><div className="import-result-grid"><div><strong>{importResult.imported}</strong><span>Imported</span></div><div><strong>{importResult.rejected}</strong><span>Rejected</span></div><div><strong>{importResult.duplicates}</strong><span>Duplicates</span></div></div><p>{importResult.message}</p>{importResult.errors?.length > 0 && <div className="validation-errors"><strong>Rows that were skipped</strong><ul>{importResult.errors.slice(0, 8).map((issue, index) => <li key={`${issue}-${index}`}>{issue}</li>)}</ul>{importResult.errors.length > 8 && <span>And {importResult.errors.length - 8} more row issue(s).</span>}</div>}<div className="dialog-actions"><button className="primary-button" onClick={() => setImportOpen(false)}>Done</button></div></> : <><div className="dialog-icon"><Upload size={20} /></div><div className="section-kicker">ADD TO YOUR VAULT</div><h2 id="import-title">Import messages from CSV</h2><p>Choose a .csv file to preview its records. Valid records are saved in this app’s local backend data file; nothing is sent to an external service.</p><div className="csv-instructions"><strong>Required columns</strong><code>sender, subject, body, timestamp, source</code><span>Use ISO 8601 timestamps with a timezone, such as <code>2026-10-20T10:00:00Z</code>. Subject may be blank for SMS. A subject makes a record an email.</span><span>Limits: 1 MB per file and 200 message rows. Keep only fictional or data you are authorized to import.</span></div><label className="file-picker"><Upload size={16} /><span>{importFile ? importFile.name : 'Choose a CSV file'}</span><input type="file" accept=".csv,text/csv,application/csv" aria-label="Choose a CSV file" onChange={handleFileSelection} /></label>{importError && <div className="import-error" role="alert">{importError}</div>}{importPreview?.fileError && <div className="import-error" role="alert">{importPreview.fileError}</div>}{importPreview && !importPreview.fileError && <div className="preview-panel"><div className="preview-heading"><strong>Preview</strong><span>{importPreview.rows.filter((row) => row.valid).length} valid · {importPreview.errors.length} with errors</span></div><div className="preview-table-wrap"><table className="preview-table"><thead><tr><th>Type</th><th>Sender</th><th>Subject</th><th>Message</th><th>Timestamp</th></tr></thead><tbody>{importPreview.rows.slice(0, 8).map((row) => <tr className={row.valid ? '' : 'invalid-preview-row'} key={row.line}><td>{row.type}</td><td>{row.sender || '—'}</td><td>{row.subject || '—'}</td><td>{row.body || '—'}</td><td>{row.timestamp || '—'}{!row.valid && <span className="preview-row-error">{importPreview.errors.find((issue) => issue.startsWith(`Line ${row.line}:`))}</span>}</td></tr>)}</tbody></table></div>{importPreview.rows.length > 8 && <span className="preview-more">Showing first 8 of {importPreview.rows.length} rows.</span>}</div>}{!importResult && importPreview?.errors?.length > 0 && <div className="validation-errors"><strong>Rows with validation issues</strong><ul>{importPreview.errors.slice(0, 8).map((issue) => <li key={issue}>{issue}</li>)}</ul>{importPreview.errors.length > 8 && <span>And {importPreview.errors.length - 8} more row issue(s).</span>}</div>}<div className="dialog-actions"><button className="secondary-button" disabled={importing} onClick={() => setImportOpen(false)}>Cancel</button><button className="primary-button" disabled={!importFile || !importPreview || Boolean(importPreview.fileError) || !importPreview.rows.some((row) => row.valid) || importing} onClick={submitImport}>{importing ? 'Importing…' : <>{importPreview ? `Import ${importPreview.rows.filter((row) => row.valid).length} valid rows` : 'Import records'} <ArrowRight size={15} /></>}</button></div></>}</section></div>}
    </div>
  );
}

export default App;
