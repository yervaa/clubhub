export const EVENT_TYPE_OPTIONS = [
  "Meeting",
  "Workshop",
  "Social",
  "Competition",
  "Fundraiser",
  "Service",
  "Other",
] as const;

export type EventType = (typeof EVENT_TYPE_OPTIONS)[number];

export function normalizeEventType(value: string | null | undefined): EventType {
  if (value && EVENT_TYPE_OPTIONS.includes(value as EventType)) {
    return value as EventType;
  }

  return "Other";
}
