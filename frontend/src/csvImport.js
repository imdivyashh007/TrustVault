const requiredColumns = ['sender', 'subject', 'body', 'timestamp', 'source'];
const maxFileBytes = 1024 * 1024;
const maxRows = 200;
const fieldLimits = { sender: 200, subject: 500, body: 20000, timestamp: 40, source: 200 };

function readRows(text) {
  const rows = [];
  let cells = [];
  let value = '';
  let inQuotes = false;
  let afterQuote = false;
  let line = 1;
  let rowLine = 1;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (inQuotes) {
      if (character === '"') {
        if (text[index + 1] === '"') {
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
      if (value.trim()) return { rows, error: `Line ${line}: a quote must begin at the start of a CSV field.` };
      value = '';
      inQuotes = true;
      afterQuote = false;
    } else if (character === ',') {
      cells.push(value.trim());
      value = '';
      afterQuote = false;
    } else if (character === '\n' || character === '\r') {
      if (character === '\r' && text[index + 1] === '\n') index += 1;
      cells.push(value.trim());
      if (cells.some(Boolean)) rows.push({ cells, line: rowLine });
      cells = [];
      value = '';
      afterQuote = false;
      line += 1;
      rowLine = line;
    } else if (!afterQuote) value += character;
  }

  if (inQuotes) return { rows, error: `Line ${rowLine}: an opening quote was not closed.` };
  if (cells.length || value.length || afterQuote) {
    cells.push(value.trim());
    if (cells.some(Boolean)) rows.push({ cells, line: rowLine });
  }
  return { rows };
}

export function previewCsvImport(text, fileSize) {
  if (fileSize > maxFileBytes) return { fileError: 'Choose a CSV file smaller than 1 MB.', rows: [], errors: [] };
  if (!text.trim()) return { fileError: 'This CSV file is empty.', rows: [], errors: [] };

  const parsed = readRows(text.replace(/^\uFEFF/, ''));
  if (parsed.error) return { fileError: parsed.error, rows: [], errors: [] };
  if (parsed.rows.length < 2) return { fileError: 'Add a header row and at least one message row to the CSV.', rows: [], errors: [] };

  const [headerRow, ...records] = parsed.rows;
  const headers = headerRow.cells.map((header) => header.trim().toLowerCase());
  const missing = requiredColumns.filter((column) => !headers.includes(column));
  if (missing.length) return { fileError: `Missing required columns: ${missing.join(', ')}.`, rows: [], errors: [] };
  if (records.length > maxRows) return { fileError: `This file has ${records.length} message rows; the limit is ${maxRows}.`, rows: [], errors: [] };
  const indexes = Object.fromEntries(requiredColumns.map((column) => [column, headers.indexOf(column)]));
  const errors = [];
  const rows = records.map(({ cells, line }) => {
    const record = Object.fromEntries(requiredColumns.map((column) => [column, cells[indexes[column]] || '']));
    const issues = [];
    if (cells.length !== headers.length) issues.push(`Expected ${headers.length} columns, found ${cells.length}.`);
    for (const column of ['sender', 'body', 'timestamp', 'source']) {
      if (!record[column].trim()) issues.push(`${column} is required.`);
    }
    if (record.timestamp.trim()) {
      const validIsoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:?\d{2})$/i.test(record.timestamp);
      if (!validIsoTimestamp || !Number.isFinite(Date.parse(record.timestamp))) issues.push('Timestamp must be ISO 8601 with a timezone.');
    }
    const oversizedField = Object.entries(fieldLimits).find(([field, limit]) => record[field].length > limit);
    if (oversizedField) issues.push(`${oversizedField[0]} exceeds the ${oversizedField[1]} character limit.`);
    if (issues.length) errors.push(`Line ${line}: ${issues.join(' ')}`);
    return { ...record, line, valid: issues.length === 0, type: record.subject.trim() ? 'Email' : 'SMS' };
  });
  return { rows, errors, fileError: '' };
}
