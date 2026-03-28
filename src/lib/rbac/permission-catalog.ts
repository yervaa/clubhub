// Permission catalog — human-readable labels, descriptions, and category grouping
// for all 26 permission keys. Safe to import in client components (no server-only code).

import type { PermissionKey } from "@/lib/rbac/permissions";

export type PermissionCategory =
  | "Club"
  | "Members"
  | "Roles"
  | "Announcements"
  | "Events"
  | "Attendance"
  | "Reflections"
  | "Insights"
  | "Audit"
  | "Tasks";

export type PermissionMeta = {
  label: string;
  description: string;
  category: PermissionCategory;
};

export const PERMISSION_CATEGORIES: PermissionCategory[] = [
  "Club",
  "Members",
  "Roles",
  "Announcements",
  "Events",
  "Attendance",
  "Reflections",
  "Insights",
  "Audit",
  "Tasks",
];

export const PERMISSION_CATALOG: Record<PermissionKey, PermissionMeta> = {
  // Club
  "club.manage_settings": {
    label: "Manage Settings",
    description: "Edit club name, description, and join code.",
    category: "Club",
  },
  "club.delete": {
    label: "Delete Club",
    description: "Permanently delete this club and all its data.",
    category: "Club",
  },
  "club.transfer_presidency": {
    label: "Transfer Presidency",
    description: "Assign the President role to another member.",
    category: "Club",
  },
  // Members
  "members.view": {
    label: "View Members",
    description: "See the member roster and profile information.",
    category: "Members",
  },
  "members.invite": {
    label: "Invite Members",
    description: "Share the join code and invite links.",
    category: "Members",
  },
  "members.remove": {
    label: "Remove Members",
    description: "Remove members from the club.",
    category: "Members",
  },
  "members.assign_roles": {
    label: "Assign Roles",
    description: "Grant or revoke RBAC roles for any member.",
    category: "Members",
  },
  // Roles
  "roles.create": {
    label: "Create Roles",
    description: "Create new custom roles for this club.",
    category: "Roles",
  },
  "roles.edit": {
    label: "Edit Roles",
    description: "Rename and update custom role descriptions.",
    category: "Roles",
  },
  "roles.delete": {
    label: "Delete Roles",
    description: "Remove custom roles from the club.",
    category: "Roles",
  },
  "roles.assign_permissions": {
    label: "Assign Permissions",
    description: "Add or remove permissions from any role.",
    category: "Roles",
  },
  // Announcements
  "announcements.create": {
    label: "Create Announcements",
    description: "Post new announcements to the club.",
    category: "Announcements",
  },
  "announcements.edit": {
    label: "Edit Announcements",
    description: "Edit existing club announcements.",
    category: "Announcements",
  },
  "announcements.delete": {
    label: "Delete Announcements",
    description: "Remove announcements from the club.",
    category: "Announcements",
  },
  // Events
  "events.create": {
    label: "Create Events",
    description: "Schedule new events for the club.",
    category: "Events",
  },
  "events.edit": {
    label: "Edit Events",
    description: "Modify details of existing events.",
    category: "Events",
  },
  "events.delete": {
    label: "Delete Events",
    description: "Remove events from the club calendar.",
    category: "Events",
  },
  // Attendance
  "attendance.mark": {
    label: "Mark Attendance",
    description: "Record member attendance for events.",
    category: "Attendance",
  },
  "attendance.edit": {
    label: "Edit Attendance",
    description: "Correct or unmark attendance records.",
    category: "Attendance",
  },
  // Reflections
  "reflections.create": {
    label: "Write Reflections",
    description: "Add officer reflections after events.",
    category: "Reflections",
  },
  "reflections.edit": {
    label: "Edit Reflections",
    description: "Update existing officer reflections.",
    category: "Reflections",
  },
  "reflections.delete": {
    label: "Delete Reflections",
    description: "Remove reflections from past events.",
    category: "Reflections",
  },
  // Insights
  "insights.view": {
    label: "View Insights",
    description: "Access club analytics and engagement data.",
    category: "Insights",
  },
  "insights.export": {
    label: "Export Insights",
    description: "Download analytics data as a report.",
    category: "Insights",
  },
  // Audit
  "audit_logs.view": {
    label: "View Audit Log",
    description: "See a history of club management actions.",
    category: "Audit",
  },
  // Tasks
  "tasks.view": {
    label: "View All Tasks",
    description: "See all tasks in the club, not just assigned ones.",
    category: "Tasks",
  },
  "tasks.create": {
    label: "Create Tasks",
    description: "Create new tasks and assign them to members.",
    category: "Tasks",
  },
  "tasks.edit": {
    label: "Edit Tasks",
    description: "Edit the title, description, and details of any task.",
    category: "Tasks",
  },
  "tasks.delete": {
    label: "Delete Tasks",
    description: "Permanently delete club tasks.",
    category: "Tasks",
  },
  "tasks.assign": {
    label: "Assign Tasks",
    description: "Assign or unassign members on any task.",
    category: "Tasks",
  },
  "tasks.complete": {
    label: "Complete Tasks",
    description: "Mark assigned tasks as complete.",
    category: "Tasks",
  },
};

/** Returns only the keys that belong to a given category, in declaration order. */
export function getPermissionsByCategory(category: PermissionCategory): PermissionKey[] {
  return (Object.entries(PERMISSION_CATALOG) as [PermissionKey, PermissionMeta][])
    .filter(([, meta]) => meta.category === category)
    .map(([key]) => key);
}
