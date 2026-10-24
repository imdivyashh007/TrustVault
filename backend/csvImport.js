import { createHash, randomUUID } from 'node:crypto';

export const MAX_CSV_BYTES = 1024 * 1024;
export const MAX_IMPORT_ROWS = 200;
export const REQUIRED_COLUMNS = ['sender', 'subject', 'body', 'timestamp', 'source'];

function parseCsvRows(csvText) {
  const rows = [];
  let row = [];
  let value = '';
  let inQuotes = false;
  let afterQuote = false;
  let line = 1;
  let rowLine = 1;

  for (let index = 0; index < csvText.length; index += 1) {
    const character = csvText[index];

    if (inQuotes) {
      if (character === '"') {
        if (csvText[index + 1] === '"') {
          value += '"';
          index += 1;
        } else {
          inQuotes = false;
          afterQuote = true;
        }
      } else {
        value += character;
        if (character === '\n') line += 1;
      }
      continue;
    }

    if (afterQuote && character !== ',' && character !== '\r' && character !== '\n' && character !== ' ' && character !== '\t') {
      return { rows, error: `Line ${line}: unexpected character after a closing quote.` };
    }

    if (character === '"') {
      if (value.length > 0 && value.trim().length > 0) {
        return { rows, error: `Line ${line}: a quote must begin at the start of a CSV field.` };
      }
      value = '';
      inQuotes = true;
      afterQuote = false;
    } else if (character === ',') {
      row.push(afterQuote ? value.trim() : value.trim());
      value = '';
      afterQuote = false;
    } else if (character === '\n' || character === '\r') {
      if (character === '\r' && csvText[index + 1] === '\n') index += 1;
      row.push(value.trim());
      if (row.some((cell) => cell !== '')) rows.push({ cells: row, line: rowLine });
      row = [];
      value = '';
      afterQuote = false;
      line += 1;
      rowLine = line;
    } else if (!afterQuote) {
      value += character;
    }
  }

  if (inQuotes) return { rows, error: `Line ${rowLine}: an opening quote was not closed.` };
  if (row.length || value.length || afterQuote) {
    row.push(value.trim());
    if (row.some((cell) => cell !== '')) rows.push({ cells: row, line: rowLine });
  }
  return { rows };
}

export function parseAndValidateCsv(csvText, existingMessages = []) {
  const errors = [];
  if (typeof csvText !== 'string' || !csvText.trim()) {
    return { records: [], rejected: 0, duplicates: 0, errors: ['The CSV file is empty.'] };
  }

  const byteLength = Buffer.byteLength(csvText, 'utf8');
  if (byteLength > MAX_CSV_BYTES) {
    return { records: [], rejected: 0, duplicates: 0, errors: ['The CSV file exceeds the 1 MB size limit.'] };
  }

  const parsed = parseCsvRows(csvText.replace(/^\uFEFF/, ''));
  if (parsed.error) return { records: [], rejected: 0, duplicates: 0, errors: [parsed.error] };
  if (parsed.rows.length < 2) return { records: [], rejected: 0, duplicates: 0, errors: ['The CSV must contain a header row and at least one message row.'] };

  const [headerRow, ...dataRows] = parsed.rows;
  const headers = headerRow.cells.map((header) => header.trim().toLowerCase());
  const missingColumns = REQUIRED_COLUMNS.filter((column) => !headers.includes(column));
  if (missingColumns.length) {
    return { records: [], rejected: 0, duplicates: 0, errors: [`Missing required column${missingColumns.length > 1 ? 's' : ''}: ${missingColumns.join(', ')}.`] };
  }
  const columnIndexes = Object.fromEntries(REQUIRED_COLUMNS.map((column) => [column, headers.indexOf(column)]));
  if (dataRows.length > MAX_IMPORT_ROWS) {
    return { records: [], rejected: 0, duplicates: 0, errors: [`This file has ${dataRows.length} rows. The limit is ${MAX_IMPORT_ROWS} message rows per import.`] };
  }

  const existingKeys = new Set(existingMessages.map(messageKey));
  const seenKeys = new Set(existingKeys);
  const records = [];
  let rejected = 0;
  let duplicates = 0;

  for (const { cells, line } of dataRows) {
    if (cells.length !== headers.length) {
      rejected += 1;
      errors.push(`Line ${line}: expected ${headers.length} columns, found ${cells.length}.`);
      continue;
    }

    const record = Object.fromEntries(REQUIRED_COLUMNS.map((column) => [column, cells[columnIndexes[column]] || '']));
    const missing = ['sender', 'body', 'timestamp', 'source'].filter((column) => !record[column].trim());
    const parsedTimestamp = Date.parse(record.timestamp);
    if (missing.length) {
      rejected += 1;
      errors.push(`Line ${line}: ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} required.`);
      continue;
    }
    if (!Number.isFinite(parsedTimestamp) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:?\d{2})$/i.test(record.timestamp)) {
      rejected += 1;
      errors.push(`Line ${line}: timestamp must be an ISO 8601 date and time with a timezone (for example 2026-10-20T10:00:00Z).`);
      continue;
    }
    const fieldLimits = { sender: 200, subject: 500, body: 20000, timestamp: 40, source: 200 };
    const oversizedField = Object.entries(fieldLimits).find(([field, limit]) => record[field].length > limit);
    if (oversizedField) {
      rejected += 1;
      errors.push(`Line ${line}: ${oversizedField[0]} exceeds the ${oversizedField[1]} character limit.`);
      continue;
    }

    const timestamp = new Date(parsedTimestamp).toISOString();
    const subject = record.subject.trim();
    const body = record.body.trim();
    const normalized = {
      id: `import-${randomUUID()}`,
      sender: record.sender.trim(),
      type: subject ? 'Email' : 'SMS',
      source: record.source.trim(),
      subject,
      preview: body.length > 100 ? `${body.slice(0, 97)}…` : body,
      body,
      timestamp,
      date: timestamp,
      analysisStatus: 'unchecked',
      analysisNote: 'Imported record. Scam analysis has not been run on this message.',
    };
    const key = messageKey(normalized);
    if (seenKeys.has(key)) {
      duplicates += 1;
      continue;
    }
    seenKeys.add(key);
    records.push(normalized);
  }

  return { records, rejected, duplicates, errors };
}

function messageKey(message) {
  const values = [message.sender, message.subject, message.body, message.timestamp || message.date]
    .map((value) => String(value || '').trim().toLowerCase());
  return createHash('sha256').update(values.join('\u001f')).digest('hex');
}
