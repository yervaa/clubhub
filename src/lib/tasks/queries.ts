import "server-only";
import { createClient } from "@/lib/supabase/server";

// ─── Shared types ─────────────────────────────────────────────────────────────

export type TaskStatus = "todo" | "in_progress" | "blocked" | "completed";
export type TaskPriority = "low" | "medium" | "high" | "urgent";

export type TaskAssignee = {
  userId: string;
  fullName: string | null;
  email: string | null;
};

export type ClubTask = {
  id: string;
  clubId: string;
  title: string;
  description: string | null;
  status: TaskStatus;
  priority: TaskPriority;
  dueAt: string | null;
  dueAtIso: string | null;
  createdBy: string;
  createdByName: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  assignees: TaskAssignee[];
  isOverdue: boolean;
};

// ─── Raw Supabase row types ───────────────────────────────────────────────────

type RawAssigneeRow = {
  user_id: string;
  profiles: { full_name: string | null; email: string | null } | null;
};

type RawTaskRow = {
  id: string;
  club_id: string;
  title: string;
  description: string | null;
  status: string;
  priority: string;
  due_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  creator: { full_name: string | null; email: string | null } | null;
  club_task_assignees: RawAssigneeRow[];
};

// ─── Formatters ───────────────────────────────────────────────────────────────

function formatDate(iso: string | null): string | null {
  if (!iso) return null;
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function normalizeTask(raw: RawTaskRow): ClubTask {
  const now = new Date();
  const dueAt = raw.due_at ? new Date(raw.due_at) : null;
  const isOverdue =
    dueAt !== null &&
    raw.status !== "completed" &&
    dueAt < now;

  return {
    id: raw.id,
    clubId: raw.club_id,
    title: raw.title,
    description: raw.description,
    status: raw.status as TaskStatus,
    priority: raw.priority as TaskPriority,
    dueAt: formatDate(raw.due_at),
    dueAtIso: raw.due_at,
    createdBy: raw.created_by,
    createdByName: raw.creator?.full_name ?? raw.creator?.email ?? null,
    createdAt: formatDate(raw.created_at) ?? raw.created_at,
    updatedAt: raw.updated_at,
    completedAt: formatDate(raw.completed_at),
    assignees: (raw.club_task_assignees ?? []).map((a) => ({
      userId: a.user_id,
      fullName: a.profiles?.full_name ?? null,
      email: a.profiles?.email ?? null,
    })),
    isOverdue,
  };
}

// ─── Queries ──────────────────────────────────────────────────────────────────

/**
 * Returns all tasks visible to the current user for a given club.
 * RLS gates visibility: officers see all tasks, members see assigned/created tasks.
 */
export async function getClubTasks(clubId: string): Promise<ClubTask[]> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("club_tasks")
    .select(`
      id, club_id, title, description, status, priority,
      due_at, created_by, created_at, updated_at, completed_at,
      creator:profiles!club_tasks_created_by_fkey ( full_name, email ),
      club_task_assignees (
        user_id,
        profiles!club_task_assignees_user_id_fkey ( full_name, email )
      )
    `)
    .eq("club_id", clubId)
    .order("created_at", { ascending: false });

  if (error) {
    console.error("[tasks] getClubTasks error:", error.message);
    return [];
  }

  return ((data ?? []) as unknown as RawTaskRow[]).map(normalizeTask);
}

/**
 * Returns tasks assigned to the given user in a club.
 * Used for the "My Tasks" section.
 */
export async function getMyClubTasks(
  clubId: string,
  userId: string,
): Promise<ClubTask[]> {
  const supabase = await createClient();

  // Fetch task IDs assigned to this user first, then fetch those tasks.
  const { data: assigneeRows } = await supabase
    .from("club_task_assignees")
    .select("task_id")
    .eq("user_id", userId);

  const taskIds = (assigneeRows ?? []).map((r) => r.task_id);
  if (taskIds.length === 0) return [];

  const { data, error } = await supabase
    .from("club_tasks")
    .select(`
      id, club_id, title, description, status, priority,
      due_at, created_by, created_at, updated_at, completed_at,
      creator:profiles!club_tasks_created_by_fkey ( full_name, email ),
      club_task_assignees (
        user_id,
        profiles!club_task_assignees_user_id_fkey ( full_name, email )
      )
    `)
    .eq("club_id", clubId)
    .in("id", taskIds)
    .neq("status", "completed")
    .order("due_at", { ascending: true, nullsFirst: false });

  if (error) {
    console.error("[tasks] getMyClubTasks error:", error.message);
    return [];
  }

  return ((data ?? []) as unknown as RawTaskRow[]).map(normalizeTask);
}
