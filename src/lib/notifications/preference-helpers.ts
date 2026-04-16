import type { NotificationType } from "@/lib/notifications/notification-types";
import { notificationTypeToGroup, type ResolvedNotificationPreferences } from "@/lib/notifications/preference-model";
import { isUserInQuietHours } from "@/lib/notifications/quiet-hours";

/** Whether an in-app `notifications` row should be created for this type. */
export function shouldReceiveInAppNotification(
  prefs: ResolvedNotificationPreferences,
  type: NotificationType,
): boolean {
  const group = notificationTypeToGroup(type);
  return prefs.inApp[group];
}

/**
 * Whether an immediate email should be sent (category enabled and not in quiet hours).
 * During quiet hours, email is suppressed; users can rely on weekly digest for coverage.
 */
export function shouldSendImmediateEmailNotification(
  prefs: ResolvedNotificationPreferences,
  type: NotificationType,
  now: Date,
): boolean {
  const group = notificationTypeToGroup(type);
  if (!prefs.email[group]) return false;
  if (isUserInQuietHours(prefs, now)) return false;
  return true;
}

export { isUserInQuietHours } from "@/lib/notifications/quiet-hours";

export function isWeeklyDigestEnabled(prefs: ResolvedNotificationPreferences): boolean {
  return prefs.weeklyDigestEnabled;
}
