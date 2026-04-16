import "server-only";

import { createBulkNotifications, createNotification } from "@/lib/notifications/create-notification";
import { createAdminClient } from "@/lib/supabase/admin";
import type { PermissionKey } from "@/lib/rbac/permissions";

async function listUserIdsWithPermission(clubId: string, permissionKey: PermissionKey): Promise<string[]> {
  const admin = createAdminClient();
  const { data, error } = await admin.rpc("list_club_members_with_permission", {
    p_club_id: clubId,
    p_permission_key: permissionKey,
  });
  if (error) {
    console.error("[advisor-notify] list_club_members_with_permission", error.message);
    return [];
  }
  return (data ?? []) as string[];
}

export async function notifyApproversEventSubmitted(args: {
  clubId: string;
  actorId: string;
  eventId: string;
  title: string;
}): Promise<void> {
  const approvers = await listUserIdsWithPermission(args.clubId, "events.approve");
  const recipients = approvers.filter((id) => id !== args.actorId);
  if (recipients.length === 0) return;
  await createBulkNotifications(
    recipients.map((userId) => ({
      userId,
      clubId: args.clubId,
      type: "approval.pending" as const,
      title: "Event pending approval",
      body: `${args.title} is waiting for your review.`,
      href: `/clubs/${args.clubId}/advisor`,
      metadata: { kind: "event", event_id: args.eventId },
    })),
  );
}

export async function notifyApproversAnnouncementSubmitted(args: {
  clubId: string;
  actorId: string;
  announcementId: string;
  title: string;
}): Promise<void> {
  const approvers = await listUserIdsWithPermission(args.clubId, "announcements.approve");
  const recipients = approvers.filter((id) => id !== args.actorId);
  if (recipients.length === 0) return;
  await createBulkNotifications(
    recipients.map((userId) => ({
      userId,
      clubId: args.clubId,
      type: "approval.pending" as const,
      title: "Announcement pending approval",
      body: `${args.title} is waiting for your review.`,
      href: `/clubs/${args.clubId}/advisor`,
      metadata: { kind: "announcement", announcement_id: args.announcementId },
    })),
  );
}

export async function notifyOrganizerApprovalDecision(args: {
  clubId: string;
  organizerId: string;
  kind: "event" | "announcement";
  title: string;
  approved: boolean;
  reason: string | null;
  entityHref: string;
}): Promise<void> {
  if (!args.organizerId) return;
  await createNotification({
    userId: args.organizerId,
    clubId: args.clubId,
    type: "approval.resolved" as const,
    title: args.approved
      ? args.kind === "event"
        ? "Event approved"
        : "Announcement approved"
      : args.kind === "event"
        ? "Event not approved"
        : "Announcement not approved",
    body: args.approved
      ? `${args.title} was approved and is visible to members.`
      : `${args.title} was not approved.${args.reason ? ` Note: ${args.reason}` : ""}`,
    href: args.entityHref,
    metadata: { kind: args.kind, approved: args.approved },
  });
}
