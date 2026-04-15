export type ActivityEventType =
  | "announcement.created"
  | "event.created"
  | "rsvp.submitted"
  | "attendance.marked"
  | "role.assigned"
  | "role.removed";

export type ActivityFeedItem = {
  id: string;
  type: ActivityEventType;
  actorName: string;
  actionLabel: string;
  targetLabel: string;
  timestamp: string;
  href: string | null;
  clubId: string;
  clubName: string | null;
  metadata: Record<string, unknown>;
};

export type ActivityEventInput = {
  type: ActivityEventType;
  actorId: string;
  clubId: string;
  entityId?: string | null;
  targetLabel: string;
  href?: string | null;
  metadata?: Record<string, unknown>;
};
