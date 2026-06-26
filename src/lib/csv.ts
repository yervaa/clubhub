/**
 * Minimal RFC 4180-style CSV helpers for downloads (Excel-friendly with BOM at call site).
 */

/**
 * Characters that trigger formula evaluation when a CSV is opened in
 * Excel / Google Sheets. A cell beginning with any of these is prefixed
 * with a single quote to neutralize formula (CSV) injection.
 */
const FORMULA_INJECTION_PREFIXES = new Set(["=", "+", "-", "@", "\t", "\r"]);

export function csvEscapeCell(value: string): string {
  let normalized = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.length > 0 && FORMULA_INJECTION_PREFIXES.has(normalized[0]!)) {
    normalized = `'${normalized}`;
  }
  if (/[",\n]/.test(normalized)) {
    return `"${normalized.replace(/"/g, '""')}"`;
  }
  return normalized;
}

export function csvJoinRow(cells: string[]): string {
  return cells.map(csvEscapeCell).join(",");
}
