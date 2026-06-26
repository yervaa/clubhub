"use client";

import { useState, useActionState, useRef, useEffect } from "react";
import {
  createTaskAction,
  updateTaskAction,
  updateTaskStatusAction,
  deleteTaskAction,
  type TaskActionResult,
} from "@/lib/tasks/actions";
import { EmptyState } from "@/components/ui/empty-state";
import type { ClubTask, TaskStatus, TaskPriority, TaskAssignee } from "@/lib/tasks/queries";

// ─── Types ────────────────────────────────────────────────────────────────────

type ClubMember = { userId: string; fullName: string | null; email: string | null };

type TaskPermissions = {
  canView: boolean;
  canCreate: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canAssign: boolean;
  canComplete: boolean;
};

type Props = {
  clubId: string;
  clubName: string;
  currentUserId: string;
  tasks: ClubTask[];
  myTasks: ClubTask[];
  clubMembers: ClubMember[];
  permissions: TaskPermissions;
};

// ─── Status / priority config ─────────────────────────────────────────────────

const STATUS_CONFIG: Record<TaskStatus, { label: string; bg: string; text: string; dot: string }> = {
  todo:        { label: "To Do",       bg: "bg-slate-100",  text: "text-slate-600", dot: "bg-slate-400"  },
  in_progress: { label: "In Progress", bg: "bg-blue-100",   text: "text-blue-700",  dot: "bg-blue-500"   },
  blocked:     { label: "Blocked",     bg: "bg-red-100",    text: "text-red-700",   dot: "bg-red-500"    },
  completed:   { label: "Completed",   bg: "bg-green-100",  text: "text-green-700", dot: "bg-green-500"  },
};

const PRIORITY_CONFIG: Record<TaskPriority, { label: string; bg: string; text: string }> = {
  low:    { label: "Low",    bg: "bg-slate-100",  text: "text-slate-500"  },
  medium: { label: "Medium", bg: "bg-blue-100",   text: "text-blue-600"   },
  high:   { label: "High",   bg: "bg-amber-100",  text: "text-amber-700"  },
  urgent: { label: "Urgent", bg: "bg-red-100",    text: "text-red-700"    },
};

const PRIORITY_LEFT_BORDER: Record<TaskPriority, string> = {
  low:    "border-l-slate-300",
  medium: "border-l-blue-400",
  high:   "border-l-amber-400",
  urgent: "border-l-red-500",
};

// ─── Filter type ──────────────────────────────────────────────────────────────

type FilterStatus = TaskStatus | "all";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function displayName(m: { fullName: string | null; email: string | null } | null): string {
  if (!m) return "Unknown";
  const n = m.fullName?.trim();
  if (n) return n;
  return "Member";
}

function initials(name: string): string {
  return name
    .split(" ")
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}

function AssigneeAvatar({ assignee }: { assignee: TaskAssignee }) {
  const name = displayName(assignee);
  return (
    <span
      className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-slate-700 text-[9px] font-semibold text-white"
      title={name}
    >
      {initials(name)}
    </span>
  );
}

function StatusBadge({ status }: { status: TaskStatus }) {
  const cfg = STATUS_CONFIG[status];
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${cfg.bg} ${cfg.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: TaskPriority }) {
  const cfg = PRIORITY_CONFIG[priority];
  return (
    <span className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${cfg.bg} ${cfg.text}`}>
      {cfg.label}
    </span>
  );
}

// ─── Task Form (Create & Edit) ────────────────────────────────────────────────

type TaskFormProps = {
  clubId: string;
  clubMembers: ClubMember[];
  permissions: TaskPermissions;
  editTask?: ClubTask;
  onSuccess: () => void;
  onCancel: () => void;
};

function TaskForm({ clubId, clubMembers, permissions, editTask, onSuccess, onCancel }: TaskFormProps) {
  const isEditing = Boolean(editTask);
  const action = isEditing ? updateTaskAction : createTaskAction;

  const [state, formAction, isPending] = useActionState<TaskActionResult, FormData>(action, { ok: true });

  const [selectedAssignees, setSelectedAssignees] = useState<string[]>(
    editTask?.assignees.map((a) => a.userId) ?? [],
  );

  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state.ok && !isPending) {
      if (formRef.current?.dataset.submitted === "true") {
        onSuccess();
        formRef.current.dataset.submitted = "";
      }
    }
  }, [state, isPending, onSuccess]);

  function toggleAssignee(userId: string) {
    setSelectedAssignees((prev) =>
      prev.includes(userId) ? prev.filter((id) => id !== userId) : [...prev, userId],
    );
  }

  return (
    <form
      ref={formRef}
      action={(fd) => {
        if (formRef.current) formRef.current.dataset.submitted = "true";
        fd.set("assignee_ids", JSON.stringify(selectedAssignees));
        formAction(fd);
      }}
      className="space-y-4"
    >
      <input type="hidden" name="club_id" value={clubId} />
      {editTask && <input type="hidden" name="task_id" value={editTask.id} />}

      <div>
        <label htmlFor="task-title" className="mb-1.5 block text-sm font-medium text-slate-700">
          Title <span className="text-red-500">*</span>
        </label>
        <input
          id="task-title"
          name="title"
          type="text"
          required
          defaultValue={editTask?.title}
          className="input-control"
          placeholder="What needs to be done?"
        />
      </div>

      <div>
        <label htmlFor="task-desc" className="mb-1.5 block text-sm font-medium text-slate-700">
          Description
        </label>
        <textarea
          id="task-desc"
          name="description"
          rows={3}
          defaultValue={editTask?.description ?? ""}
          className="textarea-control"
          placeholder="Optional details, context, or instructions…"
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="task-priority" className="mb-1.5 block text-sm font-medium text-slate-700">
            Priority
          </label>
          <select
            id="task-priority"
            name="priority"
            defaultValue={editTask?.priority ?? "medium"}
            className="input-control"
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="urgent">Urgent</option>
          </select>
        </div>

        <div>
          <label htmlFor="task-status" className="mb-1.5 block text-sm font-medium text-slate-700">
            Status
          </label>
          <select
            id="task-status"
            name="status"
            defaultValue={editTask?.status ?? "todo"}
            className="input-control"
          >
            <option value="todo">To Do</option>
            <option value="in_progress">In Progress</option>
            <option value="blocked">Blocked</option>
            <option value="completed">Completed</option>
          </select>
        </div>
      </div>

      <div>
        <label htmlFor="task-due" className="mb-1.5 block text-sm font-medium text-slate-700">
          Due Date
        </label>
        <input
          id="task-due"
          name="due_at"
          type="datetime-local"
          defaultValue={
            editTask?.dueAtIso
              ? new Date(editTask.dueAtIso).toISOString().slice(0, 16)
              : ""
          }
          className="input-control"
        />
      </div>

      {(permissions.canAssign || permissions.canCreate) && clubMembers.length > 0 && (
        <div>
          <p className="mb-2 block text-sm font-medium text-slate-700">Assignees</p>
          <div className="grid gap-1 sm:grid-cols-2">
            {clubMembers.map((member) => {
              const name = displayName(member);
              const checked = selectedAssignees.includes(member.userId);
              return (
                <label
                  key={member.userId}
                  className={`flex cursor-pointer items-center gap-2.5 rounded-lg border px-3 py-2 text-sm transition ${
                    checked
                      ? "border-slate-800 bg-slate-900 text-white"
                      : "border-slate-200 text-slate-700 hover:bg-slate-50"
                  }`}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={checked}
                    onChange={() => toggleAssignee(member.userId)}
                  />
                  <span
                    className={`flex h-5 w-5 flex-shrink-0 items-center justify-center rounded border text-xs ${
                      checked ? "border-white bg-white text-slate-900" : "border-slate-300"
                    }`}
                  >
                    {checked && (
                      <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                  </span>
                  <span className="truncate font-medium">{name}</span>
                </label>
              );
            })}
          </div>
        </div>
      )}

      {!state.ok && (
        <p className="alert-error">{(state as { ok: false; error: string }).error}</p>
      )}

      <div className="flex items-center gap-3 pt-1">
        <button type="submit" disabled={isPending} className="btn-primary">
          {isPending ? "Saving…" : isEditing ? "Save Changes" : "Create Task"}
        </button>
        <button type="button" onClick={onCancel} className="btn-secondary">
          Cancel
        </button>
      </div>
    </form>
  );
}

// ─── Task Row ─────────────────────────────────────────────────────────────────

type TaskRowProps = {
  task: ClubTask;
  currentUserId: string;
  permissions: TaskPermissions;
  clubMembers: ClubMember[];
  clubId: string;
  isEditing: boolean;
  onEdit: () => void;
  onCancelEdit: () => void;
  onEditSuccess: () => void;
};

function TaskRow({
  task,
  currentUserId,
  permissions,
  clubMembers,
  clubId,
  isEditing,
  onEdit,
  onCancelEdit,
  onEditSuccess,
}: TaskRowProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const [statusState, statusAction, isStatusPending] = useActionState<TaskActionResult, FormData>(
    updateTaskStatusAction,
    { ok: true },
  );
  const [deleteState, deleteAction, isDeletePending] = useActionState<TaskActionResult, FormData>(
    deleteTaskAction,
    { ok: true },
  );

  const isAssignee = task.assignees.some((a) => a.userId === currentUserId);
  const canChangeStatus = permissions.canEdit || (permissions.canComplete && isAssignee);
  const canComplete = permissions.canEdit || (permissions.canComplete && isAssignee);
  const borderClass = PRIORITY_LEFT_BORDER[task.priority];

  if (isEditing) {
    return (
      <div className={`task-row task-row--editing border-l-4 px-4 py-4 ${borderClass}`}>
        <p className="mb-4 text-sm font-semibold text-slate-900">Edit Task</p>
        <TaskForm
          clubId={clubId}
          clubMembers={clubMembers}
          permissions={permissions}
          editTask={task}
          onSuccess={onEditSuccess}
          onCancel={onCancelEdit}
        />
      </div>
    );
  }

  return (
    <div
      className={`task-row border-l-4 ${borderClass} ${task.status === "completed" ? "opacity-60" : ""}`}
    >
      <div className="flex items-start">
        {/* Clickable expand area */}
        <button
          type="button"
          onClick={() => setIsExpanded((v) => !v)}
          className="task-row__toggle min-w-0 flex-1 px-4 py-3 text-left"
          aria-expanded={isExpanded}
        >
          {/* Line 1: title + badges */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span
              className={`text-sm font-medium text-slate-900 ${
                task.status === "completed" ? "line-through text-slate-500" : ""
              }`}
            >
              {task.title}
            </span>
            <StatusBadge status={task.status} />
            <PriorityBadge priority={task.priority} />
            {task.isOverdue && (
              <span className="inline-flex items-center gap-0.5 rounded-full bg-red-100 px-1.5 py-0.5 text-[10px] font-semibold text-red-700">
                <svg className="h-2.5 w-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Overdue
              </span>
            )}
          </div>

          {/* Line 2: description (collapsed = 1-line truncate) */}
          {task.description && (
            <p
              className={`mt-1 text-xs leading-relaxed text-slate-500 ${
                isExpanded ? "" : "truncate"
              }`}
            >
              {task.description}
            </p>
          )}

          {/* Line 3: assignees + due + creator + chevron */}
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5">
            {task.assignees.length > 0 ? (
              <div className="flex -space-x-0.5">
                {task.assignees.slice(0, 5).map((a) => (
                  <AssigneeAvatar key={a.userId} assignee={a} />
                ))}
                {task.assignees.length > 5 && (
                  <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-slate-200 text-[9px] font-semibold text-slate-600">
                    +{task.assignees.length - 5}
                  </span>
                )}
              </div>
            ) : (
              <span className="text-xs text-slate-400">Unassigned</span>
            )}

            {task.dueAt && (
              <span className={`text-xs ${task.isOverdue ? "text-red-600 font-medium" : "text-slate-400"}`}>
                Due {task.dueAt}
              </span>
            )}

            {task.createdByName && (
              <span className="text-xs text-slate-400">by {task.createdByName}</span>
            )}

            <svg
              className={`ml-auto h-3 w-3 flex-shrink-0 text-slate-400 transition-transform duration-150 ${
                isExpanded ? "rotate-180" : ""
              }`}
              fill="none"
              viewBox="0 0 20 20"
            >
              <path
                fillRule="evenodd"
                d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
                clipRule="evenodd"
                fill="currentColor"
              />
            </svg>
          </div>
        </button>

        {/* Action buttons (always visible, outside the expand toggle) */}
        <div className="flex shrink-0 items-center gap-0.5 px-2 py-3">
          {canComplete && task.status !== "completed" && (
            <form
              action={(fd) => {
                fd.set("club_id", clubId);
                fd.set("task_id", task.id);
                fd.set("status", "completed");
                statusAction(fd);
              }}
            >
              <button
                type="submit"
                disabled={isStatusPending}
                title="Mark complete"
                className="task-action-btn"
              >
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                </svg>
              </button>
            </form>
          )}

          {permissions.canEdit && (
            <button
              type="button"
              onClick={() => { onEdit(); setIsExpanded(false); }}
              title="Edit task"
              className="task-action-btn"
            >
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            </button>
          )}

          {permissions.canDelete && (
            <form
              action={(fd) => {
                fd.set("club_id", clubId);
                fd.set("task_id", task.id);
                deleteAction(fd);
              }}
            >
              <button
                type="submit"
                disabled={isDeletePending}
                title="Delete task"
                onClick={(e) => {
                  if (!window.confirm("Delete this task? This cannot be undone.")) {
                    e.preventDefault();
                  }
                }}
                className="task-action-btn task-action-btn--danger"
              >
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </form>
          )}
        </div>
      </div>

      {/* Expanded panel */}
      {isExpanded && (
        <div className="task-row__panel border-t border-[color:var(--color-border-tertiary)] px-4 py-3">
          {canChangeStatus && task.status !== "completed" && (
            <form
              action={(fd) => {
                fd.set("club_id", clubId);
                fd.set("task_id", task.id);
                statusAction(fd);
              }}
              className="flex flex-wrap items-center gap-2"
            >
              <span className="text-xs font-medium text-slate-500">Move to</span>
              {(["todo", "in_progress", "blocked"] as TaskStatus[])
                .filter((s) => s !== task.status)
                .map((s) => {
                  const cfg = STATUS_CONFIG[s];
                  return (
                    <button
                      key={s}
                      type="submit"
                      name="status"
                      value={s}
                      disabled={isStatusPending}
                      className={`rounded-full px-3 py-1 text-xs font-semibold transition hover:opacity-80 ${cfg.bg} ${cfg.text}`}
                    >
                      {cfg.label}
                    </button>
                  );
                })}
            </form>
          )}
          {!statusState.ok && (
            <p className="mt-2 text-xs text-red-600">{(statusState as { ok: false; error: string }).error}</p>
          )}
        </div>
      )}

      {!deleteState.ok && (
        <p className="border-t border-red-100 px-4 py-2 text-xs text-red-600">
          {(deleteState as { ok: false; error: string }).error}
        </p>
      )}
    </div>
  );
}

// ─── Main section component ───────────────────────────────────────────────────

export function ClubTasksSection({
  clubId,
  currentUserId,
  tasks,
  myTasks,
  clubMembers,
  permissions,
}: Props) {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingTaskId, setEditingTaskId] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState<FilterStatus>("all");
  const [filterAssigneeMe, setFilterAssigneeMe] = useState(false);
  const [search, setSearch] = useState("");

  const total = tasks.length;
  const openCount = tasks.filter((t) => t.status !== "completed").length;
  const overdueCount = tasks.filter((t) => t.isOverdue).length;
  const completedCount = tasks.filter((t) => t.status === "completed").length;

  const filteredTasks = tasks.filter((t) => {
    if (filterStatus !== "all" && t.status !== filterStatus) return false;
    if (filterAssigneeMe && !t.assignees.some((a) => a.userId === currentUserId)) return false;
    if (search && !t.title.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const filterTabs: { label: string; value: FilterStatus; count?: number }[] = [
    { label: "All", value: "all", count: total },
    { label: "To Do", value: "todo" },
    { label: "In Progress", value: "in_progress" },
    { label: "Blocked", value: "blocked" },
    { label: "Completed", value: "completed", count: completedCount },
  ];

  return (
    <div className="page-sections">
      {/* Page header: title + Add Task */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 sm:text-2xl">Tasks</h1>
        {permissions.canCreate && (
          <button
            type="button"
            onClick={() => setShowCreateForm(true)}
            className="btn-primary shrink-0"
          >
            + Add Task
          </button>
        )}
      </div>

      {/* Compact stat tiles */}
      <div className="club-tasks-stats">
        <div className="club-tasks-stat">
          <p className="club-tasks-stat__value">{total}</p>
          <p className="club-tasks-stat__label">Total</p>
        </div>
        <div className="club-tasks-stat">
          <p className="club-tasks-stat__value">{openCount}</p>
          <p className="club-tasks-stat__label">Open</p>
        </div>
        <div className="club-tasks-stat club-tasks-stat--overdue">
          <p className="club-tasks-stat__value">{overdueCount}</p>
          <p className="club-tasks-stat__label">Overdue</p>
        </div>
        <div className="club-tasks-stat club-tasks-stat--mine">
          <p className="club-tasks-stat__value">{myTasks.length}</p>
          <p className="club-tasks-stat__label">Mine</p>
        </div>
      </div>

      {/* Create form (inline card, shown when button pressed) */}
      {showCreateForm && (
        <div className="card-surface p-4 sm:p-5">
          <div className="mb-4 flex items-center justify-between gap-4">
            <h2 className="text-base font-semibold text-slate-900">Create Task</h2>
            <button
              type="button"
              onClick={() => setShowCreateForm(false)}
              className="rounded-md p-1 text-slate-400 hover:text-slate-600"
              aria-label="Close"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <TaskForm
            clubId={clubId}
            clubMembers={clubMembers}
            permissions={permissions}
            onSuccess={() => setShowCreateForm(false)}
            onCancel={() => setShowCreateForm(false)}
          />
        </div>
      )}

      {/* ONE card: filter bar + task rows */}
      <div className="card-surface overflow-hidden p-0">
        {/* Filter toolbar */}
        <div className="club-tasks-toolbar">
          {/* Status pills */}
          <div className="flex gap-1.5 overflow-x-auto pb-0.5 [-ms-overflow-style:none] [scrollbar-width:none] sm:flex-wrap sm:overflow-visible [&::-webkit-scrollbar]:hidden">
            {filterTabs.map((tab) => (
              <button
                key={tab.value}
                type="button"
                onClick={() => setFilterStatus(tab.value)}
                className={`shrink-0 min-h-9 rounded-full px-3 py-1.5 text-xs font-semibold transition sm:min-h-0 sm:py-1 ${
                  filterStatus === tab.value
                    ? "bg-slate-900 text-white"
                    : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                }`}
              >
                {tab.label}
                {tab.count !== undefined && (
                  <span
                    className={`ml-1 rounded-full px-1.5 py-0.5 text-[10px] ${
                      filterStatus === tab.value
                        ? "bg-white/20 text-white"
                        : "bg-slate-200 text-slate-500"
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Assignee + overdue + search row */}
          <div className="mt-2.5 flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
            <button
              type="button"
              onClick={() => setFilterAssigneeMe((v) => !v)}
              className={`flex min-h-9 w-full items-center justify-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-semibold transition sm:w-auto sm:min-h-0 sm:py-1 ${
                filterAssigneeMe
                  ? "bg-emerald-700 text-white"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
              Assigned to me
            </button>

            {overdueCount > 0 && (
              <span className="flex min-h-9 w-full items-center justify-center gap-1.5 rounded-full bg-red-100 px-3 py-1.5 text-xs font-semibold text-red-700 sm:w-auto sm:min-h-0 sm:py-1">
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {overdueCount} overdue
              </span>
            )}

            <div className="relative w-full sm:ml-auto sm:w-52">
              <svg className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search tasks…"
                className="min-h-9 w-full rounded-full border border-slate-200 bg-white py-1.5 pl-9 pr-3 text-xs text-slate-700 placeholder-slate-400 focus:border-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-200 sm:min-h-0 sm:py-1"
              />
            </div>
          </div>
        </div>

        {/* Task list */}
        <div className="club-tasks-list">
          {filteredTasks.length === 0 ? (
            tasks.length === 0 ? (
              <div className="px-4 py-8">
                <EmptyState
                  icon="ti-checkbox"
                  title="No tasks yet"
                  description={
                    permissions.canCreate
                      ? "Add an assignment so members know what to work on."
                      : "Assignments and to-dos for this club show up here."
                  }
                  action={
                    permissions.canCreate
                      ? { label: "Create task", onClick: () => setShowCreateForm(true) }
                      : undefined
                  }
                  embedded
                />
              </div>
            ) : (
              <div className="px-6 py-10 text-center">
                <p className="text-sm font-semibold text-slate-700">No tasks match your filters</p>
                <p className="mt-1 text-xs text-slate-500">Try adjusting the status filter or search term.</p>
              </div>
            )
          ) : (
            filteredTasks.map((task) => (
              <TaskRow
                key={task.id}
                task={task}
                currentUserId={currentUserId}
                permissions={permissions}
                clubMembers={clubMembers}
                clubId={clubId}
                isEditing={editingTaskId === task.id}
                onEdit={() => setEditingTaskId(task.id)}
                onCancelEdit={() => setEditingTaskId(null)}
                onEditSuccess={() => setEditingTaskId(null)}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
