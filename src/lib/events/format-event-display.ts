/**
 * Consistent event datetime display (no raw locale strings with seconds).
 */

export function parseEventInstant(value: Date | string): Date {
  return value instanceof Date ? value : new Date(value);
}

export function formatEventDateMedium(d: Date): string {
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/** e.g. 3:30 PM — never includes seconds */
export function formatEventTimeShort(d: Date): string {
  return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

export function formatEventDateAndTime(d: Date): { date: string; time: string } {
  return { date: formatEventDateMedium(d), time: formatEventTimeShort(d) };
}
