import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createImportHandler } from '../server.js';
import { parseAndValidateCsv } from '../csvImport.js';
import { createMessageStore } from '../messageStore.js';
import { previewCsvImport } from '../../frontend/src/csvImport.js';

const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
const fixtureCsv = await readFile(path.join(projectRoot, 'examples/fictional-messages.csv'), 'utf8');
const demoMessages = JSON.parse(await readFile(path.join(projectRoot, 'backend/data/messages.json'), 'utf8'))
  .filter((message) => message.id.startsWith('demo-'));

async function postImport(store, csv = fixtureCsv) {
  let statusCode = 200;
  let payload;
  const response = {
    status(code) {
      statusCode = code;
      return this;
    },
    json(value) {
      payload = value;
      return value;
    },
  };
  await createImportHandler(store)({ body: { filename: 'fictional-messages.csv', csv } }, response, (error) => {
    throw error;
  });
  return { statusCode, payload };
}

test('first import adds fixture rows while preserving demo records and persists after reload', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-import-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createMessageStore(path.join(directory, 'messages.json'));
  await store.write(demoMessages);

  const { statusCode, payload } = await postImport(store);
  assert.equal(statusCode, 200);
  assert.deepEqual(payload, {
    imported: 2,
    rejected: 0,
    invalidRows: 0,
    duplicates: 0,
    errors: [],
    message: '2 records were saved to the local TrustVault data store.',
  });

  const reloadedStore = createMessageStore(path.join(directory, 'messages.json'));
  const saved = await reloadedStore.read();
  assert.equal(saved.length, 5);
  assert.deepEqual(saved.slice(0, 3).map((message) => message.id), ['demo-1', 'demo-2', 'demo-3']);
  const imported = saved.filter((message) => message.id.startsWith('import-'));
  assert.equal(imported.length, 2);
  assert.ok(imported.every((message) => message.analysis && ['low', 'medium', 'high'].includes(message.analysis.riskLevel)));
});

test('repeated import returns separate duplicate and rejected counts', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-import-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createMessageStore(path.join(directory, 'messages.json'));
  await store.write(demoMessages);

  const first = await postImport(store);
  assert.equal(first.payload.imported, 2);
  const repeated = await postImport(store);
  assert.equal(repeated.statusCode, 200);
  assert.deepEqual(repeated.payload, {
    imported: 0,
    rejected: 0,
    invalidRows: 0,
    duplicates: 2,
    errors: [],
    message: 'No new records were imported. 2 duplicates were already in your vault and skipped; duplicates are not counted as rejected.',
  });
  assert.equal((await store.read()).length, 5);
});

test('valid CSV parser accepts email and SMS rows with optional SMS subjects', () => {
  const result = parseAndValidateCsv(fixtureCsv, demoMessages);
  assert.equal(result.records.length, 2);
  assert.equal(result.records[0].type, 'Email');
  assert.equal(result.records[1].type, 'SMS');
  assert.equal(result.rejected, 0);
});

test('missing required columns and empty files are rejected clearly', () => {
  const missing = parseAndValidateCsv('sender,body,timestamp\nCafe,Hello,2026-10-20T10:00:00Z');
  assert.match(missing.errors[0], /subject, source/);
  const empty = parseAndValidateCsv('  \n');
  assert.match(empty.errors[0], /CSV file is empty/);
});

test('invalid rows count as rejected and valid rows in the same file are still imported', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-import-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createMessageStore(path.join(directory, 'messages.json'));
  await store.write(demoMessages);
  const csv = [
    'sender,subject,body,timestamp,source',
    'Valid Cafe,Pickup,Your sample order is ready.,2026-10-20T10:00:00Z,Fictional sample',
    'Invalid Library,,A reserved book notice,not-a-date,Fictional sample',
    'Malformed Row,Only two',
  ].join('\n');
  const preview = previewCsvImport(csv, Buffer.byteLength(csv));
  const response = await postImport(store, csv);

  assert.deepEqual(preview.rows.map((row) => row.valid), [true, false, false]);
  assert.equal(response.payload.imported, 1);
  assert.equal(response.payload.rejected, 2);
  assert.equal(response.payload.invalidRows, 2);
  assert.equal(response.payload.duplicates, 0);
  assert.equal(response.payload.errors.length, 2);
  assert.equal((await store.read()).length, 4);
});

test('frontend preview and backend agree on field-size validation', () => {
  const csv = `sender,subject,body,timestamp,source\nCafe,${'x'.repeat(501)},Body,2026-10-20T10:00:00Z,Fictional sample`;
  const preview = previewCsvImport(csv, Buffer.byteLength(csv));
  const server = parseAndValidateCsv(csv);
  assert.equal(preview.rows[0].valid, false);
  assert.equal(server.rejected, 1);
});
