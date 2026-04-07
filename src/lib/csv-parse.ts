/**
 * Minimal RFC 4180-style CSV parsing for single-line uploads (member import).
 * Handles quoted fields, escaped quotes, and CRLF / LF newlines.
 */

export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = "";
  let inQuotes = false;

  const pushCell = () => {
    row.push(cur);
    cur = "";
  };

  const pushRow = () => {
    if (row.length > 0 || cur.length > 0) {
      pushCell();
      if (row.some((cell) => cell.length > 0)) {
        rows.push(row);
      }
      row = [];
    }
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;

    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
      continue;
    }

    if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      pushCell();
    } else if (c === "\n") {
      pushRow();
    } else if (c === "\r") {
      if (text[i + 1] === "\n") {
        i++;
      }
      pushRow();
    } else {
      cur += c;
    }
  }

  if (cur.length > 0 || row.length > 0) {
    pushCell();
    if (row.some((cell) => cell.length > 0)) {
      rows.push(row);
    }
  }

  return rows;
}

export function stripUtf8Bom(text: string): string {
  if (text.charCodeAt(0) === 0xfeff) {
    return text.slice(1);
  }
  return text;
}
