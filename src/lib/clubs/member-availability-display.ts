/** Client-safe labels for `club_member_availability_slots.day_of_week` (1 = Mon … 7 = Sun). */

export const AVAILABILITY_WEEKDAY_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

export type AvailabilityDayOfWeek = 1 | 2 | 3 | 4 | 5 | 6 | 7;

export function availabilityWeekdayShort(day: number): string {
  if (day < 1 || day > 7) return "?";
  return AVAILABILITY_WEEKDAY_SHORT[day - 1];
}

/** Normalize Postgres `time` strings (e.g. `15:30:00`) to `HH:MM` for display and inputs. */
export function normalizeAvailabilityTime(raw: string | null | undefined): string | null {
  if (raw == null || raw === "") return null;
  const s = String(raw).trim();
  const m = /^(\d{1,2}):(\d{2})(?::\d{2})?/.exec(s);
  if (!m) return null;
  const h = Number.parseInt(m[1], 10);
  const min = Number.parseInt(m[2], 10);
  if (!Number.isFinite(h) || !Number.isFinite(min)) return null;
  return `${String(h).padStart(2, "0")}:${String(min).padStart(2, "0")}`;
}

export function formatAvailabilitySlotLine(slot: {
  dayOfWeek: number;
  timeStart: string | null;
  timeEnd: string | null;
}): string {
  const day = availabilityWeekdayShort(slot.dayOfWeek);
  const a = normalizeAvailabilityTime(slot.timeStart);
  const b = normalizeAvailabilityTime(slot.timeEnd);
  if (a == null || b == null) {
    return `${day} · flexible / all day`;
  }
  return `${day} · ${a}–${b}`;
}

export function compareAvailabilitySlots(
  a: { dayOfWeek: number; timeStart: string | null; timeEnd: string | null; createdAt: string },
  b: { dayOfWeek: number; timeStart: string | null; timeEnd: string | null; createdAt: string },
): number {
  if (a.dayOfWeek !== b.dayOfWeek) return a.dayOfWeek - b.dayOfWeek;
  const as = a.timeStart ?? "";
  const bs = b.timeStart ?? "";
  if (as !== bs) return as.localeCompare(bs);
  return a.createdAt.localeCompare(b.createdAt);
}
