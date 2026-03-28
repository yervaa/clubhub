// Role template config — client-safe (no server-only imports).
// Each template defines a starting set of permissions for common school club roles.
// Created roles are normal custom roles; templates only seed the initial state.

import type { PermissionKey } from "@/lib/rbac/permissions";

// ─── Types ────────────────────────────────────────────────────────────────────

export type RoleTemplateKey =
  | "vice_president"
  | "secretary"
  | "treasurer"
  | "historian"
  | "social_media_manager"
  | "advisor"
  | "blank";

export type RoleTemplate = {
  key: RoleTemplateKey;
  name: string;
  description: string;
  /** Short label shown on the template card, ≤ 50 chars. */
  tagline: string;
  /** Emoji used as the card icon. */
  emoji: string;
  permissions: PermissionKey[];
};

// ─── Template definitions ─────────────────────────────────────────────────────

export const ROLE_TEMPLATES: Record<RoleTemplateKey, RoleTemplate> = {
  vice_president: {
    key: "vice_president",
    name: "Vice President",
    description: "Second-in-command with broad management authority.",
    tagline: "Full management authority, minus top-level controls.",
    emoji: "🏅",
    permissions: [
      "club.manage_settings",
      "members.view",
      "members.invite",
      "members.remove",
      "members.assign_roles",
      "announcements.create",
      "announcements.edit",
      "announcements.delete",
      "events.create",
      "events.edit",
      "events.delete",
      "attendance.mark",
      "attendance.edit",
      "reflections.create",
      "reflections.edit",
      "reflections.delete",
      "insights.view",
      "insights.export",
      "tasks.view",
      "tasks.create",
      "tasks.edit",
      "tasks.assign",
      "tasks.complete",
    ],
  },

  secretary: {
    key: "secretary",
    name: "Secretary",
    description: "Handles communications, records, and event coordination.",
    tagline: "Announcements, events, and member visibility.",
    emoji: "📋",
    permissions: [
      "members.view",
      "members.invite",
      "announcements.create",
      "announcements.edit",
      "announcements.delete",
      "events.create",
      "events.edit",
      "insights.view",
      "tasks.view",
      "tasks.create",
      "tasks.assign",
      "tasks.complete",
    ],
  },

  treasurer: {
    key: "treasurer",
    name: "Treasurer",
    description: "Oversees club records and engagement analytics.",
    tagline: "Insights, exports, and read-only visibility.",
    emoji: "💰",
    permissions: [
      "members.view",
      "insights.view",
      "insights.export",
    ],
  },

  historian: {
    key: "historian",
    name: "Historian",
    description: "Documents club events and maintains records over time.",
    tagline: "Events, reflections, and club documentation.",
    emoji: "📸",
    permissions: [
      "members.view",
      "events.create",
      "events.edit",
      "reflections.create",
      "reflections.edit",
      "insights.view",
    ],
  },

  social_media_manager: {
    key: "social_media_manager",
    name: "Social Media Manager",
    description: "Manages club communications and public-facing content.",
    tagline: "Announcements, events, and engagement data.",
    emoji: "📣",
    permissions: [
      "members.view",
      "announcements.create",
      "announcements.edit",
      "announcements.delete",
      "events.create",
      "events.edit",
      "insights.view",
    ],
  },

  advisor: {
    key: "advisor",
    name: "Advisor",
    description: "Read-only oversight of all club activity and governance logs.",
    tagline: "Visibility across members, insights, and audit history.",
    emoji: "🎓",
    permissions: [
      "members.view",
      "insights.view",
      "insights.export",
      "audit_logs.view",
    ],
  },

  blank: {
    key: "blank",
    name: "Custom Role",
    description: "Start from scratch and build a fully custom permission set.",
    tagline: "No permissions — configure everything yourself.",
    emoji: "✏️",
    permissions: [],
  },
};

// Ordered list for UI rendering (Blank always last).
export const ROLE_TEMPLATE_ORDER: RoleTemplateKey[] = [
  "vice_president",
  "secretary",
  "treasurer",
  "historian",
  "social_media_manager",
  "advisor",
  "blank",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

export function isValidTemplateKey(key: string): key is RoleTemplateKey {
  return key in ROLE_TEMPLATES;
}
