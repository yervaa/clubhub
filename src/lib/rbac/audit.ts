import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";

// ─── Action keys ──────────────────────────────────────────────────────────────
// Machine-readable keys stored in club_audit_logs.action.
// Keep this in sync with UI rendering in governance-section.tsx.

export type AuditAction =
  | "role.created"
  | "role.updated"
  | "role.deleted"
  | "role.assigned"
  | "role.removed"
  | "president.added"
  | "president.removed"
  | "presidency.transferred";

// ─── Input shape ──────────────────────────────────────────────────────────────

export type AuditEventInput = {
  clubId: string;
  actorId: string;
  action: AuditAction;
  /** UUID of the member affected by this action, if applicable. */
  targetUserId?: string | null;
  /** UUID of the role affected by this action, if applicable. */
  targetRoleId?: string | null;
  /**
   * Supplementary structured data.
   * Always store role_name here for role.deleted events because the target_role_id
   * is set to NULL by the FK's ON DELETE SET NULL clause after the row is removed.
   */
  metadata?: Record<string, unknown>;
};

// ─── Resolved entry shape (used by the UI layer) ──────────────────────────────

export type AuditLogEntry = {
  id: string;
  action: AuditAction;
  /** Resolved display name of the actor (full_name or email). */
  actorName: string;
  /** Resolved display name of the target user, or null. */
  targetUserName: string | null;
  /** Resolved role name, or role_name from metadata for deleted roles, or null. */
  targetRoleName: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
};

// ─── Write helper ─────────────────────────────────────────────────────────────
// Uses the service-role admin client so the insert bypasses RLS.
// Audit writes are server-only and must never be triggered from the client.

export async function logAuditEvent(event: AuditEventInput): Promise<void> {
  const admin = createAdminClient();

  const { error } = await admin.from("club_audit_logs").insert({
    club_id: event.clubId,
    actor_id: event.actorId,
    action: event.action,
    target_user_id: event.targetUserId ?? null,
    target_role_id: event.targetRoleId ?? null,
    metadata: event.metadata ?? {},
  });

  if (error) {
    // Audit failure is non-fatal — we log it but never block the triggering action.
    console.error("[audit] Failed to write audit event:", event.action, error.message);
  }
}
