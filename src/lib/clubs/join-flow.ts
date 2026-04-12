/**
 * Join-by-code flow: canonical redirect messages and query-param decoding for join URLs.
 * Logged-in users use `/clubs/join` (app shell); public invite links use `/join` (sign-in gate).
 * Keep server redirects and the join pages in sync.
 */

export const JOIN_REDIRECT_MESSAGES = {
  joinedImmediate: "You're in! You've joined the club.",
  requestSubmitted: "Request submitted. An officer will approve or decline it soon.",
  requestAlreadyPending:
    "You already have a pending request for this club. Check back after an officer reviews it.",
  invalidOrArchived:
    "We couldn't find an active club with that code. It may be incorrect, or the club may be archived.",
  alreadyMember: "You're already a member of this club.",
} as const;

/** Decode `success` or `error` query values from `redirect(...)` (+ and percent-encoding). */
export function decodeJoinPageMessage(raw: string | undefined): string | null {
  if (raw === undefined || raw === "") return null;
  const s = typeof raw === "string" ? raw : String(raw);
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s.replace(/\+/g, " ");
  }
}

/** Treat as a neutral "all good" state, not a hard error (show Open club, not red alert). */
export function joinMessageIsAlreadyMember(message: string): boolean {
  return /already\s+a\s+member/i.test(message);
}
