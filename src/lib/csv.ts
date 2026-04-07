/**
 * Minimal RFC 4180-style CSV helpers for downloads (Excel-friendly with BOM at call site).
 */

export function csvEscapeCell(value: string): string {
  const normalized = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (/[",\n]/.test(normalized)) {
    return `"${normalized.replace(/"/g, '""')}"`;
  }
  return normalized;
}

export function csvJoinRow(cells: string[]): string {
  return cells.map(csvEscapeCell).join(",");
}
