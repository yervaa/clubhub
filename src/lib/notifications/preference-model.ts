/** Preference buckets mapped from `notifications.type` strings. */
export type NotificationPreferenceGroup =
  | "announcements"
  | "events"
  | "reminders"
  | "role_membership"
  | "activity";

/** Row shape from `notification_preferences` (snake_case). */
export type NotificationPreferencesRow = {
  user_id: string;
  in_app_announcements: boolean;
  email_announcements: boolean;
  in_app_events: boolean;
  email_events: boolean;
  in_app_reminders: boolean;
  email_reminders: boolean;
  in_app_role_membership: boolean;
  email_role_membership: boolean;
  in_app_activity: boolean;
  email_activity: boolean;
  quiet_hours_enabled: boolean;
  quiet_hours_start: string | null;
  quiet_hours_end: string | null;
  timezone: string;
  weekly_digest_enabled: boolean;
};

/** Resolved prefs used by notification + email helpers (always defined). */
export type ResolvedNotificationPreferences = {
  inApp: Record<NotificationPreferenceGroup, boolean>;
  email: Record<NotificationPreferenceGroup, boolean>;
  quietHoursEnabled: boolean;
  quietHoursStart: string | null;
  quietHoursEnd: string | null;
  timezone: string;
  weeklyDigestEnabled: boolean;
};

/** Defaults: all in-app on; email on for major categories only; digest off; quiet hours off. */
/** DB-shaped defaults (matches `050_notification_preferences.sql`) for new users / missing rows. */
export const NOTIFICATION_PREFERENCES_FORM_DEFAULTS: Omit<NotificationPreferencesRow, "user_id"> = {
  in_app_announcements: true,
  email_announcements: true,
  in_app_events: true,
  email_events: true,
  in_app_reminders: true,
  email_reminders: false,
  in_app_role_membership: true,
  email_role_membership: true,
  in_app_activity: true,
  email_activity: false,
  quiet_hours_enabled: false,
  quiet_hours_start: null,
  quiet_hours_end: null,
  timezone: "UTC",
  weekly_digest_enabled: false,
};

export const DEFAULT_NOTIFICATION_PREFERENCES: ResolvedNotificationPreferences = {
  inApp: {
    announcements: true,
    events: true,
    reminders: true,
    role_membership: true,
    activity: true,
  },
  email: {
    announcements: true,
    events: true,
    reminders: false,
    role_membership: true,
    activity: false,
  },
  quietHoursEnabled: false,
  quietHoursStart: null,
  quietHoursEnd: null,
  timezone: "UTC",
  weeklyDigestEnabled: false,
};

export function notificationTypeToGroup(type: string): NotificationPreferenceGroup {
  switch (type) {
    case "announcement.posted":
    case "announcement.created":
    case "announcement_created":
    case "poll.created":
    case "poll_created":
      return "announcements";
    case "event.created":
    case "rsvp.submitted":
    case "attendance.marked":
      return "events";
    case "event_reminder":
      return "reminders";
    case "role.assigned":
    case "role.removed":
      return "role_membership";
    case "task.assigned":
    case "task_assigned":
    case "approval.pending":
    case "approval.resolved":
      return "activity";
    default:
      return "activity";
  }
}

export function rowToResolvedPreferences(row: NotificationPreferencesRow): ResolvedNotificationPreferences {
  return {
    inApp: {
      announcements: row.in_app_announcements,
      events: row.in_app_events,
      reminders: row.in_app_reminders,
      role_membership: row.in_app_role_membership,
      activity: row.in_app_activity,
    },
    email: {
      announcements: row.email_announcements,
      events: row.email_events,
      reminders: row.email_reminders,
      role_membership: row.email_role_membership,
      activity: row.email_activity,
    },
    quietHoursEnabled: row.quiet_hours_enabled,
    quietHoursStart: row.quiet_hours_start,
    quietHoursEnd: row.quiet_hours_end,
    timezone: row.timezone?.trim() || "UTC",
    weeklyDigestEnabled: row.weekly_digest_enabled,
  };
}
