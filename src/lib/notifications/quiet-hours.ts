import type { ResolvedNotificationPreferences } from "@/lib/notifications/preference-model";

function parseHHMMToMinutes(value: string | null): number | null {
  if (!value || !/^\d{2}:\d{2}$/.test(value.trim())) return null;
  const [h, m] = value.trim().split(":").map((x) => Number.parseInt(x, 10));
  if (!Number.isFinite(h) || !Number.isFinite(m) || h < 0 || h > 23 || m < 0 || m > 59) return null;
  return h * 60 + m;
}

/** Wall-clock minutes since midnight in `timeZone` for `date`. */
export function getLocalMinutesSinceMidnight(date: Date, timeZone: string): number | null {
  try {
    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
    const parts = fmt.formatToParts(date);
    const hour = Number.parseInt(parts.find((p) => p.type === "hour")?.value ?? "0", 10);
    const minute = Number.parseInt(parts.find((p) => p.type === "minute")?.value ?? "0", 10);
    if (!Number.isFinite(hour) || !Number.isFinite(minute)) return null;
    return hour * 60 + minute;
  } catch {
    return null;
  }
}

/**
 * Quiet window [start, end) in local minutes; if start > end the window crosses midnight.
 */
function isWithinQuietWindow(nowMin: number, startMin: number, endMin: number): boolean {
  if (startMin === endMin) return false;
  if (startMin < endMin) {
    return nowMin >= startMin && nowMin < endMin;
  }
  return nowMin >= startMin || nowMin < endMin;
}

/** When quiet hours are disabled or misconfigured, returns false. Invalid timezone falls back to UTC. */
export function isUserInQuietHours(prefs: ResolvedNotificationPreferences, now: Date): boolean {
  if (!prefs.quietHoursEnabled) return false;
  const start = parseHHMMToMinutes(prefs.quietHoursStart);
  const end = parseHHMMToMinutes(prefs.quietHoursEnd);
  if (start == null || end == null) return false;

  let tz = prefs.timezone?.trim() || "UTC";
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
  } catch {
    tz = "UTC";
  }

  const nowMin = getLocalMinutesSinceMidnight(now, tz);
  if (nowMin == null) return false;
  return isWithinQuietWindow(nowMin, start, end);
}
