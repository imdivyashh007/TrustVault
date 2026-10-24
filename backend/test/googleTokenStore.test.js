import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { GMAIL_READONLY_SCOPE } from '../googleOAuth.js';
import { createGoogleTokenBundle, createGoogleTokenStore } from '../googleTokenStore.js';
import { writeEncryptedToken } from '../encryptedTokenStore.js';

const key = Buffer.alloc(32, 41);
const validTokens = {
  access_token: 'fictional-access-token-never-for-real-use',
  refresh_token: 'fictional-refresh-token-never-for-real-use',
  expiry_date: 2_000_000_000_000,
  scope: GMAIL_READONLY_SCOPE,
};

async function withTokenStore(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-google-token-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'private', 'gmail-tokens.enc');
  const store = createGoogleTokenStore({ filePath, encryptionKey: key });
  return { directory, filePath, store };
}

test('Google token bundle allow-lists required fields and token store encrypts/decrypts the complete object', async (t) => {
  const { filePath, store } = await withTokenStore(t);
  const bundle = createGoogleTokenBundle({ ...validTokens, id_token: 'must-not-be-stored' });
  await store.write(bundle);
  const encrypted = await readFile(filePath, 'utf8');
  assert.doesNotMatch(encrypted, /fictional-access-token|fictional-refresh-token|must-not-be-stored/);
  assert.deepEqual(await store.read(), {
    version: 1,
    accessToken: validTokens.access_token,
    refreshToken: validTokens.refresh_token,
    expiryDate: validTokens.expiry_date,
    scopes: [GMAIL_READONLY_SCOPE],
  });
});

test('token store uses owner-only directory and file permissions where POSIX modes are available', { skip: process.platform === 'win32' }, async (t) => {
  const { filePath } = await withTokenStore(t);
  await createGoogleTokenStore({ filePath, encryptionKey: key }).write(createGoogleTokenBundle(validTokens));
  assert.equal((await stat(path.dirname(filePath))).mode & 0o777, 0o700);
  assert.equal((await stat(filePath)).mode & 0o777, 0o600);
});

test('token store fails closed when the dedicated encryption key is missing', async (t) => {
  const { filePath } = await withTokenStore(t);
  const noKey = createGoogleTokenStore({ filePath });
  await assert.rejects(noKey.write(createGoogleTokenBundle(validTokens)), /32-byte key/);
  await assert.rejects(noKey.read(), /32-byte key/);
});

test('token store rejects corrupt ciphertext and invalid decrypted JSON', async (t) => {
  const { filePath, store } = await withTokenStore(t);
  await store.write(createGoogleTokenBundle(validTokens));
  const contents = await readFile(filePath, 'utf8');
  const envelope = JSON.parse(contents);
  envelope.encryptedToken.tag = Buffer.alloc(16, 0).toString('base64url');
  await writeFile(filePath, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
  await assert.rejects(store.read());
  await writeEncryptedToken(filePath, '{not valid JSON', key);
  await assert.rejects(store.read(), /invalid data/);
});

test('token bundle rejects absent or broader granted scopes and malformed token fields', () => {
  assert.throws(() => createGoogleTokenBundle({ ...validTokens, scope: undefined }), /allowed Gmail read-only scope/);
  assert.throws(() => createGoogleTokenBundle({ ...validTokens, scope: `${GMAIL_READONLY_SCOPE} https://mail.google.com/` }), /outside the allowed Gmail read-only scope/);
  assert.throws(() => createGoogleTokenBundle({ ...validTokens, access_token: '' }), /access token/);
  assert.throws(() => createGoogleTokenBundle({ ...validTokens, expiry_date: 0 }), /valid token expiry/);
});

test('token store removes its local bundle idempotently without requiring remote revocation', async (t) => {
  const { filePath, store } = await withTokenStore(t);
  await store.write(createGoogleTokenBundle(validTokens));
  assert.equal(await store.remove(), true);
  assert.equal(await store.read(), null);
  assert.equal(await store.remove(), false);
});
