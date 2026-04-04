"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { hasPermission } from "@/lib/rbac/permissions";
import { createBulkNotifications } from "@/lib/notifications/create-notification";
import {
  taskCreateSchema,
  taskUpdateSchema,
  taskStatusUpdateSchema,
  taskDeleteSchema,
} from "@/lib/validation/clubs";

// ─── Result type ──────────────────────────────────────────────────────────────

export type TaskActionResult =
  | { ok: true }
  | { ok: false; error: string };

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseAssigneeIds(raw: string | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.filter((id) => typeof id === "string");
    return [];
  } catch {
    return [];
  }
}

function parseDueAt(raw: string | undefined): string | null {
  if (!raw || raw.trim() === "") return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// ─── Actions ──────────────────────────────────────────────────────────────────

export async function createTaskAction(
  prevState: TaskActionResult,
  formData: FormData,
): Promise<TaskActionResult> {
  const parsed = taskCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    title: formData.get("title"),
    description: formData.get("description") ?? "",
    status: formData.get("status") ?? "todo",
    priority: formData.get("priority") ?? "medium",
    dueAt: formData.get("due_at") ?? "",
    assigneeIds: formData.get("assignee_ids") ?? "",
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const { clubId, title, description, status, priority, dueAt, assigneeIds } = parsed.data;
  const assignees = parseAssigneeIds(assigneeIds);
  const dueAtIso = parseDueAt(dueAt);

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be logged in." };

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const canCreate = await hasPermission(user.id, clubId, "tasks.create");
  if (!canCreate) return { ok: false, error: "You do not have permission to create tasks." };

  const admin = createAdminClient();

  const { data: taskRow, error: insertErr } = await admin
    .from("club_tasks")
    .insert({
      club_id: clubId,
      title,
      description: description || null,
      status,
      priority,
      due_at: dueAtIso,
      created_by: user.id,
    })
    .select("id")
    .single();

  if (insertErr || !taskRow) {
    return { ok: false, error: insertErr?.message ?? "Failed to create task." };
  }

  // Insert assignees.
  if (assignees.length > 0) {
    const { error: assignErr } = await admin
      .from("club_task_assignees")
      .insert(assignees.map((uid) => ({ task_id: taskRow.id, user_id: uid })));

    if (assignErr) {
      console.error("[tasks] assignees insert error:", assignErr.message);
    }

    // Notify new assignees (exclude the creator from their own notification).
    const notifyIds = assignees.filter((uid) => uid !== user.id);
    if (notifyIds.length > 0) {
      await createBulkNotifications(
        notifyIds.map((uid) => ({
          userId: uid,
          clubId,
          type: "task.assigned" as const,
          title: `You were assigned a task: ${title}`,
          body: description ? description.slice(0, 100) : "A new task was assigned to you.",
          href: `/clubs/${clubId}/tasks`,
        })),
      );
    }
  }

  revalidatePath(`/clubs/${clubId}/tasks`);
  return { ok: true };
}

export async function updateTaskAction(
  prevState: TaskActionResult,
  formData: FormData,
): Promise<TaskActionResult> {
  const parsed = taskUpdateSchema.safeParse({
    clubId: formData.get("club_id"),
    taskId: formData.get("task_id"),
    title: formData.get("title"),
    description: formData.get("description") ?? "",
    status: formData.get("status"),
    priority: formData.get("priority"),
    dueAt: formData.get("due_at") ?? "",
    assigneeIds: formData.get("assignee_ids") ?? "",
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const { clubId, taskId, title, description, status, priority, dueAt, assigneeIds } = parsed.data;
  const newAssignees = parseAssigneeIds(assigneeIds);
  const dueAtIso = parseDueAt(dueAt);

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be logged in." };

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const canEdit = await hasPermission(user.id, clubId, "tasks.edit");
  if (!canEdit) return { ok: false, error: "You do not have permission to edit tasks." };

  const admin = createAdminClient();

  // Fetch current assignees to determine who is newly added.
  const { data: currentAssigneeRows } = await admin
    .from("club_task_assignees")
    .select("user_id")
    .eq("task_id", taskId);

  const currentIds = (currentAssigneeRows ?? []).map((r) => r.user_id);

  const completedAt = status === "completed" ? new Date().toISOString() : null;

  const { error: updateErr } = await admin
    .from("club_tasks")
    .update({
      title,
      description: description || null,
      status,
      priority,
      due_at: dueAtIso,
      completed_at: completedAt,
    })
    .eq("id", taskId)
    .eq("club_id", clubId);

  if (updateErr) return { ok: false, error: updateErr.message };

  // Replace assignees atomically.
  await admin.from("club_task_assignees").delete().eq("task_id", taskId);

  if (newAssignees.length > 0) {
    await admin
      .from("club_task_assignees")
      .insert(newAssignees.map((uid) => ({ task_id: taskId, user_id: uid })));
  }

  // Notify members who were newly assigned.
  const addedIds = newAssignees.filter((uid) => !currentIds.includes(uid) && uid !== user.id);
  if (addedIds.length > 0) {
    await createBulkNotifications(
      addedIds.map((uid) => ({
        userId: uid,
        clubId,
        type: "task.assigned" as const,
        title: `You were assigned a task: ${title}`,
        body: description ? description.slice(0, 100) : "A task was assigned to you.",
        href: `/clubs/${clubId}/tasks`,
      })),
    );
  }

  revalidatePath(`/clubs/${clubId}/tasks`);
  return { ok: true };
}

export async function updateTaskStatusAction(
  prevState: TaskActionResult,
  formData: FormData,
): Promise<TaskActionResult> {
  const parsed = taskStatusUpdateSchema.safeParse({
    clubId: formData.get("club_id"),
    taskId: formData.get("task_id"),
    status: formData.get("status"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const { clubId, taskId, status } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be logged in." };

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) return { ok: false, error: active.message };

  // tasks.edit lets you change any status.
  // tasks.complete lets you mark as completed if you are an assignee.
  const [canEdit, canComplete] = await Promise.all([
    hasPermission(user.id, clubId, "tasks.edit"),
    hasPermission(user.id, clubId, "tasks.complete"),
  ]);

  if (!canEdit) {
    if (!canComplete) return { ok: false, error: "You do not have permission to update tasks." };

    // complete-only permission: verify user is assigned and status is "completed".
    if (status !== "completed") {
      return { ok: false, error: "You can only mark tasks as complete." };
    }

    const admin = createAdminClient();
    const { data: assignment } = await admin
      .from("club_task_assignees")
      .select("task_id")
      .eq("task_id", taskId)
      .eq("user_id", user.id)
      .maybeSingle();

    if (!assignment) return { ok: false, error: "You are not assigned to this task." };
  }

  const admin = createAdminClient();
  const { error } = await admin
    .from("club_tasks")
    .update({
      status,
      completed_at: status === "completed" ? new Date().toISOString() : null,
    })
    .eq("id", taskId)
    .eq("club_id", clubId);

  if (error) return { ok: false, error: error.message };

  revalidatePath(`/clubs/${clubId}/tasks`);
  return { ok: true };
}

export async function deleteTaskAction(
  prevState: TaskActionResult,
  formData: FormData,
): Promise<TaskActionResult> {
  const parsed = taskDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    taskId: formData.get("task_id"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const { clubId, taskId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be logged in." };

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const canDelete = await hasPermission(user.id, clubId, "tasks.delete");
  if (!canDelete) return { ok: false, error: "You do not have permission to delete tasks." };

  const admin = createAdminClient();
  const { error } = await admin
    .from("club_tasks")
    .delete()
    .eq("id", taskId)
    .eq("club_id", clubId);

  if (error) return { ok: false, error: error.message };

  revalidatePath(`/clubs/${clubId}/tasks`);
  return { ok: true };
}
