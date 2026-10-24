# TrustVault

A beginner-friendly React and Express starter for a secure communication vault. The vault contains fictional SMS/email examples and imported records. An optional local Gmail integration previews metadata for at most five recent messages. A user can explicitly choose one supported message and request a temporary local heuristic analysis.

## Requirements

- Node.js 18 or newer
- npm

## Run locally

On first run, configure a local password in a terminal. This creates a private `.env` file with a scrypt password verifier and random session/token keys. It refuses to overwrite an existing `.env`.

```sh
cd backend
npm run setup-auth
npm run setup-message-key
npm run migrate-message-store
```

`migrate-message-store` must be run while the API is stopped. It keeps the original `backend/data/messages.json` intact, creates and verifies a private plaintext backup outside the project, then writes and verifies `backend/data/messages.encrypted.json`. Do not delete the original or the backup. The backend uses the encrypted store and fails closed if it cannot decrypt it.

Then open two terminal windows in this project folder.

Terminal 1 — start the API:

```sh
cd backend
npm install
npm run dev
```

Terminal 2 — start the frontend:

```sh
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (by default, <http://localhost:5173>). Log in with the password configured above. The API health check is at <http://localhost:4000/api/health>.

The frontend forwards `/api` requests to the loopback-only backend during development. Keep `.env` private. This is a single local user, not multi-user account security. Sessions are held in backend memory and expire after eight hours; restarting the backend logs out the browser. SMS accounts are not connected. Gmail OAuth can save a read-only token bundle encrypted locally and show only message IDs and selected headers in a transient preview.

## Optional Gmail OAuth foundation

The backend authorization-code flow requests only `https://www.googleapis.com/auth/gmail.readonly`. On successful authorization, TrustVault saves an allow-listed token bundle encrypted with AES-256-GCM in `backend/data/private/gmail-tokens.enc`; the bundle is never returned to the browser. OAuth stays disabled until the Google credentials and the existing dedicated `TOKEN_ENCRYPTION_KEY` are configured. Leave the Google settings blank to keep the entry point disabled:

```dotenv
GOOGLE_OAUTH_CLIENT_ID=
GOOGLE_OAUTH_CLIENT_SECRET=
```

To enable the flow, enable the Gmail API in your Google Cloud project, create an OAuth 2.0 **Web application** client, configure the OAuth consent screen in **Testing** mode, and add the Google account you will use as a test user. Use `http://localhost:5173` as the local frontend origin and register this exact authorized redirect URI:

```text
http://localhost:4000/api/auth/google/callback
```

Put the client ID and client secret in the private project-root `.env` file using the names above, then restart the backend. Do not put either value in frontend code. The frontend origin is fixed at `http://localhost:5173`; the callback is fixed at the URI above. The short-lived OAuth state is bound to the signed-in local TrustVault session. Before saving, the backend requires the granted scope to be exactly Gmail read-only and encrypts the complete token bundle using `TOKEN_ENCRYPTION_KEY`. The token file is stored outside the frontend with owner-only directory/file permissions and atomic replacement. The Gmail screen's **Disconnect locally** action deletes this local file; it does not revoke authorization at Google.

After connecting, **Preview recent Gmail messages** requests at most five message IDs and fetches only the `From`, `Subject`, and `Date` headers with Gmail's metadata format. The preview is held separately in the current browser view and is not added to the encrypted vault or scam analysis.

To analyze one preview item, choose **Analyze this email**, read the disclosure, then choose **Analyze selected email**. TrustVault checks that the message is still among the five recent IDs and inspects its MIME structure without requesting body data. Only a single-part top-level `text/plain` message with no filename, attachment ID, or MIME parts is supported. For an eligible message, TrustVault requests only that top-level text body, up to 64 KB. HTML, multipart, attachment-bearing, unsupported, malformed, and oversized messages are rejected. The request does not include Gmail's snippet or raw message fields, and TrustVault never calls the Gmail attachments endpoint. The backend analyzes the selected text with its local explainable heuristic, returns only the assessment and message metadata, and does not save the email or result. Analysis uses the same Gmail read-only scope; no OAuth scope change is requested.

Sender, subject, and date alone cannot reliably identify scams. The Gmail result includes risk level, indicators, reasoning, uncertainty, and suggested safe actions. The score is heuristic, not a probability or proof of fraud. Message content is not sent to an external AI service. Results exist only in temporary frontend state and clear when leaving the Gmail view, logging out, or disconnecting locally. Analysis is protected by the authenticated local session, CSRF checks, and a process-local limit of three analysis requests per client per minute. This feature is manual; there is no background analysis, durable Gmail metadata storage, or saved-analysis option.

The MIME gate intentionally supports only single-part plain text. It does not claim arbitrary Gmail messages are attachment-free. If a message does not pass the structure check, no body request is made. The metadata request reads only From, Subject, Date, and Content-Disposition; the body request's field mask includes only top-level MIME guard fields and body data, with no headers, snippets, HTML, nested MIME parts, or attachment content. The exact provider response shape is covered by mocked tests, not by tests against a real mailbox.

## Import fictional or authorized messages

In the dashboard, choose **Add to your vault**, select a `.csv` file, review its preview and validation notes, then choose **Import**. Imports are saved locally in `backend/data/messages.encrypted.json`; nothing is sent to an external service. The fictional demo messages remain available in the encrypted store.

The CSV header must include `sender,subject,body,timestamp,source`. Leave `subject` blank for an SMS; a non-empty subject is treated as email. Timestamps must be ISO 8601 with a timezone, for example `2026-10-20T10:00:00Z`. Each file is limited to 1 MB and 200 message rows. Exact repeat records are skipped and counted as duplicates. Message records are stored in a versioned AES-256-GCM encrypted file after the verified local migration; the original plaintext file remains as a private rollback source and must not be used for real mailbox data.

A small fictional example is included at `examples/fictional-messages.csv`. The message-encryption key is separate from the session and token keys. Losing it makes the encrypted store unreadable; keep the private `.env` protected and backed up securely.

## Local scam check

The Express API runs a local, explainable heuristic against each message's sender, subject, body, and any URLs found in those fields or attached URL metadata. It looks for combinations such as credential or one-time-code requests, money or gift-card requests, urgency, deceptive-looking domains, and delivery/account/refund/prize claims tied to sensitive requests or risky links. An ordinary link, payment mention, or urgent phrase by itself is not enough to mark a message for review.

Each result includes a 0–100 heuristic score, low/medium/high risk level, specific indicators, and suggested safe actions. The score is not a probability and does not prove fraud. This is a small rule-based demo, not a reputation feed, URL sandbox, machine-learning model, or guarantee that every scam will be detected. Analysis happens locally in the backend; message contents are not sent to an AI service.

Run backend import and scam-analysis tests from the `backend/` folder with:

```sh
npm test
```
