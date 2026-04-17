/** Machine-readable keys stored in `notifications.type` and used for preference routing. */
export type NotificationType =
  | "announcement.posted"
  | "announcement.created"
  | "announcement_created"
  | "poll.created"
  | "poll_created"
  | "event.created"
  | "rsvp.submitted"
  | "attendance.marked"
  | "event_reminder"
  | "role.assigned"
  | "role.removed"
  | "task.assigned"
  | "task_assigned"
  | "approval.pending"
  | "approval.resolved"
  | "dues.created"
  | "dues.paid"
  | "dues.received";

export type NotificationInput = {
  userId: string;
  clubId?: string | null;
  type: NotificationType;
  title: string;
  body: string;
  href?: string | null;
  activityEventId?: string | null;
  metadata?: Record<string, unknown>;
};
