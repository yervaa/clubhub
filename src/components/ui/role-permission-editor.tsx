"use client";

import { useState, useTransition } from "react";
import type { ClubRole } from "@/lib/rbac/role-actions";
import type { PermissionKey } from "@/lib/rbac/permissions";
import {
  PERMISSION_CATALOG,
  PERMISSION_CATEGORIES,
  getPermissionsByCategory,
} from "@/lib/rbac/permission-catalog";
import {
  saveRoleAction,
  deleteRoleAction,
  assignRoleToMemberAction,
  removeRoleFromMemberAction,
} from "@/app/(app)/clubs/rbac-actions";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";
import { PermissionCategoryBlock } from "@/components/ui/permission-category-block";

type RolePermissionEditorProps = {
  role: ClubRole;
  allPermissionKeys: PermissionKey[];
  clubId: string;
  isPresident: boolean;
  assignedMembers: MemberWithRoles[];
  unassignedMembers: MemberWithRoles[];
};

function getMemberLabel(m: MemberWithRoles): string {
  return m.fullName?.trim() || m.email?.split("@")[0] || "Unknown";
}

function getMemberInitial(m: MemberWithRoles): string {
  return getMemberLabel(m).slice(0, 1).toUpperCase();
}

export function RolePermissionEditor({
  role,
  allPermissionKeys,
  clubId,
  isPresident,
  assignedMembers,
  unassignedMembers,
}: RolePermissionEditorProps) {
  const isSystemPresident = role.name === "President" && role.isSystem;
  const isSystemRole = role.isSystem;
  const canEdit = isPresident && !isSystemPresident;

  // ── Local state ────────────────────────────────────────────────────────────
  const [localName, setLocalName] = useState(role.name);
  const [localDesc, setLocalDesc] = useState(role.description);
  const [localPerms, setLocalPerms] = useState<Set<PermissionKey>>(new Set(role.permissions));
  const [isPending, startTransition] = useTransition();

  // Assign-member picker state
  const [assignSearch, setAssignSearch] = useState("");
  const [, startAssignTransition] = useTransition();

  const permSetsEqual = (a: Set<PermissionKey>, b: Set<PermissionKey>) => {
    if (a.size !== b.size) return false;
    for (const k of a) if (!b.has(k)) return false;
    return true;
  };

  const serverPerms = new Set(role.permissions);
  const hasChanges =
    canEdit &&
    (localName.trim() !== role.name.trim() ||
      localDesc.trim() !== role.description.trim() ||
      !permSetsEqual(localPerms, serverPerms));

  function togglePermission(key: PermissionKey) {
    setLocalPerms((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function handleDiscard() {
    setLocalName(role.name);
    setLocalDesc(role.description);
    setLocalPerms(new Set(role.permissions));
  }

  function handleDelete(e: React.FormEvent<HTMLFormElement>) {
    if (!window.confirm(`Delete the "${role.name}" role? Members assigned to this role will lose its permissions.`)) {
      e.preventDefault();
    }
  }

  // ── Render helpers ─────────────────────────────────────────────────────────

  const roleBadgeColor = isSystemPresident
    ? "bg-violet-100 text-violet-700 border-violet-200"
    : isSystemRole
      ? "bg-blue-100 text-blue-700 border-blue-200"
      : "bg-emerald-100 text-emerald-700 border-emerald-200";

  return (
    <div className="card-surface flex flex-col">

      {/* ── Role header ─────────────────────────────────────────────────────── */}
      <div className="border-b border-slate-100 p-4 sm:p-6 md:p-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <span className={`flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full text-sm font-bold ${roleBadgeColor} border`}>
              {role.name.slice(0, 1).toUpperCase()}
            </span>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-bold leading-tight text-slate-900">
                  {canEdit && !isSystemRole ? (
                    <input
                      type="text"
                      value={localName}
                      onChange={(e) => setLocalName(e.target.value)}
                      maxLength={50}
                      className="min-w-0 border-b border-transparent bg-transparent text-lg font-bold text-slate-900 outline-none transition-colors hover:border-slate-300 focus:border-blue-400"
                      aria-label="Role name"
                    />
                  ) : (
                    role.name
                  )}
                </h2>
                {role.isSystem && (
                  <span className="badge-soft text-[10px]">System</span>
                )}
                {isSystemPresident && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-violet-200 bg-violet-50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-violet-700">
                    <svg className="h-2.5 w-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    Protected
                  </span>
                )}
              </div>

              {canEdit && !isSystemRole ? (
                <input
                  type="text"
                  value={localDesc}
                  onChange={(e) => setLocalDesc(e.target.value)}
                  maxLength={200}
                  placeholder="Add a short description…"
                  className="mt-1 w-full border-b border-transparent bg-transparent text-sm text-slate-500 outline-none transition-colors hover:border-slate-300 focus:border-blue-400"
                  aria-label="Role description"
                />
              ) : (
                <p className="mt-0.5 text-sm text-slate-500">
                  {role.description || <span className="italic text-slate-400">No description</span>}
                </p>
              )}
            </div>
          </div>

          {/* Delete custom role */}
          {isPresident && !isSystemRole && (
            <form action={deleteRoleAction} onSubmit={handleDelete} className="w-full sm:w-auto">
              <input type="hidden" name="club_id" value={clubId} />
              <input type="hidden" name="role_id" value={role.id} />
              <button
                type="submit"
                className="btn-danger flex w-full min-h-11 items-center justify-center gap-1.5 px-3 py-2 text-sm sm:min-h-0 sm:w-auto"
              >
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                Delete
              </button>
            </form>
          )}
        </div>
      </div>

      {/* ── President notice ─────────────────────────────────────────────────── */}
      {isSystemPresident && (
        <div className="mx-4 mt-4 flex items-start gap-3 rounded-lg border border-violet-200 bg-violet-50 p-4 text-sm text-violet-800 sm:mx-6 md:mx-8 md:mt-6">
          <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-violet-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <p className="font-semibold">All permissions, always</p>
            <p className="mt-0.5 text-violet-700">
              The President role automatically holds every permission. These settings cannot be changed.
            </p>
          </div>
        </div>
      )}

      {/* ── System role notice (non-President) ──────────────────────────────── */}
      {isSystemRole && !isSystemPresident && isPresident && (
        <div className="mx-4 mt-4 flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800 sm:mx-6 md:mx-8 md:mt-6">
          <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p>
            <span className="font-semibold">System role</span> — name and description are fixed,
            but you can customise its permissions below.
          </p>
        </div>
      )}

      {/* ── Permission editor ────────────────────────────────────────────────── */}
      <form
        action={saveRoleAction}
        onSubmit={(e) => {
          if (!canEdit) e.preventDefault();
          else startTransition(() => {});
        }}
        className="flex flex-1 flex-col"
      >
        <input type="hidden" name="club_id" value={clubId} />
        <input type="hidden" name="role_id" value={role.id} />
        <input type="hidden" name="name" value={localName} />
        <input type="hidden" name="description" value={localDesc} />

        <div className="flex-1 space-y-2 overflow-hidden px-4 pt-3 sm:px-6 sm:pt-4 md:px-8 lg:space-y-0 lg:divide-y lg:divide-slate-100">
          {PERMISSION_CATEGORIES.map((category) => {
            const keys = getPermissionsByCategory(category).filter((k) =>
              allPermissionKeys.includes(k),
            );
            if (keys.length === 0) return null;

            const allChecked = keys.every((k) => localPerms.has(k));
            const someChecked = !allChecked && keys.some((k) => localPerms.has(k));

            const selectAllBtn =
              canEdit ? (
                <button
                  type="button"
                  className="min-h-10 rounded-lg px-2 text-left text-xs font-semibold text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-800 sm:min-h-0 sm:px-0 sm:text-right"
                  onClick={() => {
                    setLocalPerms((prev) => {
                      const next = new Set(prev);
                      if (allChecked) {
                        keys.forEach((k) => next.delete(k));
                      } else {
                        keys.forEach((k) => next.add(k));
                      }
                      return next;
                    });
                  }}
                  aria-label={allChecked ? `Deselect all ${category} permissions` : `Select all ${category} permissions`}
                >
                  {allChecked ? "Deselect all" : someChecked ? "Select all" : "Select all"}
                </button>
              ) : null;

            return (
              <PermissionCategoryBlock key={category} category={category} headerRight={selectAllBtn}>
                <ul className="space-y-1" role="list">
                  {keys.map((key) => {
                    const meta = PERMISSION_CATALOG[key];
                    const checked = isSystemPresident || localPerms.has(key);
                    const disabled = !canEdit || isSystemPresident;

                    return (
                      <li key={key}>
                        <label
                          className={`flex min-h-[2.75rem] cursor-pointer select-none items-start gap-3 rounded-xl px-3 py-2.5 transition-colors sm:min-h-0 sm:rounded-lg sm:py-2.5 ${
                            disabled
                              ? "cursor-not-allowed opacity-60"
                              : "hover:bg-slate-50 active:bg-slate-100"
                          }`}
                        >
                          <span className="mt-1 flex-shrink-0 sm:mt-0.5">
                            <span
                              role="checkbox"
                              aria-checked={checked}
                              className={`flex h-5 w-5 items-center justify-center rounded border-2 transition-all sm:h-[18px] sm:w-[18px] ${
                                checked
                                  ? "border-slate-800 bg-slate-800"
                                  : "border-slate-300 bg-white"
                              } ${disabled ? "" : "group-hover:border-slate-500"}`}
                            >
                              {checked && (
                                <svg className="h-2.5 w-2.5 text-white" fill="none" viewBox="0 0 12 12" stroke="currentColor" strokeWidth={2.5}>
                                  <path d="M2 6l3 3 5-5" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                              )}
                            </span>
                            <input
                              type="checkbox"
                              name="permissions"
                              value={key}
                              checked={checked}
                              disabled={disabled}
                              onChange={() => togglePermission(key)}
                              className="sr-only"
                              aria-label={meta.label}
                            />
                          </span>

                          <span className="flex min-w-0 flex-1 flex-col gap-0 sm:flex-row sm:items-baseline sm:gap-3">
                            <span className="text-sm font-semibold leading-tight text-slate-800">
                              {meta.label}
                            </span>
                            <span className="text-xs leading-tight text-slate-400">
                              {meta.description}
                            </span>
                          </span>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              </PermissionCategoryBlock>
            );
          })}
        </div>

        {/* ── Sticky save bar ──────────────────────────────────────────────── */}
        {canEdit && (
          <div
            className={`sticky bottom-0 z-10 border-t border-slate-100 bg-white/95 px-4 py-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] backdrop-blur sm:px-6 sm:py-4 md:px-8 ${
              hasChanges ? "" : "opacity-60"
            }`}
          >
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className={`text-sm font-medium ${hasChanges ? "text-amber-700" : "text-slate-400"}`}>
                {hasChanges ? "You have unsaved changes." : "No changes to save."}
              </p>
              <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center sm:gap-3">
                <button
                  type="button"
                  onClick={handleDiscard}
                  disabled={!hasChanges || isPending}
                  className="btn-secondary order-2 min-h-11 w-full px-4 py-2.5 text-sm disabled:pointer-events-none disabled:opacity-40 sm:order-1 sm:min-h-0 sm:w-auto"
                >
                  Discard
                </button>
                <button
                  type="submit"
                  disabled={!hasChanges || isPending}
                  className="btn-primary order-1 min-h-11 w-full px-5 py-2.5 text-sm disabled:pointer-events-none disabled:opacity-40 sm:order-2 sm:min-h-0 sm:w-auto"
                >
                  {isPending ? (
                    <span className="flex items-center gap-2">
                      <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      Saving…
                    </span>
                  ) : (
                    "Save Changes"
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </form>

      {/* ── Assigned Members ─────────────────────────────────────────────────── */}
      <AssignedMembersPanel
        role={role}
        clubId={clubId}
        assignedMembers={assignedMembers}
        unassignedMembers={unassignedMembers}
        canAssignRoles={isPresident}
        assignSearch={assignSearch}
        onAssignSearchChange={setAssignSearch}
        startAssignTransition={startAssignTransition}
      />
    </div>
  );
}

// ─── Assigned Members panel (extracted to avoid deeply nested JSX) ────────────

type AssignedMembersPanelProps = {
  role: ClubRole;
  clubId: string;
  assignedMembers: MemberWithRoles[];
  unassignedMembers: MemberWithRoles[];
  canAssignRoles: boolean;
  assignSearch: string;
  onAssignSearchChange: (v: string) => void;
  startAssignTransition: (fn: () => void) => void;
};

function AssignedMembersPanel({
  role,
  clubId,
  assignedMembers,
  unassignedMembers,
  canAssignRoles,
  assignSearch,
  onAssignSearchChange,
}: AssignedMembersPanelProps) {
  const isPresidentRole = role.name === "President" && role.isSystem;

  const filteredUnassigned = unassignedMembers
    .filter((m) => {
      if (!assignSearch.trim()) return true;
      const label = getMemberLabel(m).toLowerCase();
      const email = (m.email ?? "").toLowerCase();
      const q = assignSearch.toLowerCase();
      return label.includes(q) || email.includes(q);
    })
    .slice(0, 8);

  return (
    <div className="border-t border-slate-100 px-4 py-5 sm:px-6 sm:py-6 md:px-8">
      <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="section-kicker text-slate-500">Assigned Members</p>
          <p className="mt-0.5 text-sm text-slate-500">
            {assignedMembers.length === 0
              ? "No members assigned to this role yet."
              : `${assignedMembers.length} ${assignedMembers.length === 1 ? "member" : "members"} hold this role.`}
          </p>
        </div>
        <span className="badge-soft shrink-0">{assignedMembers.length}</span>
      </div>

      {/* Current assignees */}
      {assignedMembers.length > 0 && (
        <ul className="mb-6 divide-y divide-slate-50 rounded-xl border border-slate-100 bg-slate-50/50">
          {assignedMembers.map((member) => {
            const label = getMemberLabel(member);
            const initial = getMemberInitial(member);
            const isPresident = isPresidentRole;
            // Last-President protection: disable remove if this is the only President
            const isLastPresident = isPresident && assignedMembers.length <= 1;

            return (
              <li key={member.userId} className="flex items-center gap-3 px-3 py-3 sm:px-4">
                {/* Avatar */}
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-200 text-xs font-bold text-slate-600">
                  {initial}
                </span>

                {/* Name + role pill */}
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold text-slate-900">{label}</p>
                  <p className="text-xs text-slate-400 capitalize">{member.legacyRole}</p>
                </div>

                {/* Remove */}
                {canAssignRoles && (
                  <form action={removeRoleFromMemberAction}>
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="role_id" value={role.id} />
                    <input type="hidden" name="target_user_id" value={member.userId} />
                    <button
                      type="submit"
                      disabled={isLastPresident}
                      title={isLastPresident ? "Cannot remove the last President" : `Remove ${label} from ${role.name}`}
                      className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-red-100 bg-red-50 text-red-500 transition-colors hover:bg-red-100 hover:text-red-700 disabled:cursor-not-allowed disabled:opacity-40 sm:h-7 sm:w-7"
                      aria-label={`Remove ${label}`}
                    >
                      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </form>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {/* Assign new member */}
      {canAssignRoles && unassignedMembers.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">
            Assign a member
          </p>

          {/* Search input */}
          <div className="relative mb-2">
            <svg
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
              fill="none" viewBox="0 0 24 24" stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={assignSearch}
              onChange={(e) => onAssignSearchChange(e.target.value)}
              placeholder="Search members…"
              className="input-control min-h-11 pl-9 text-sm sm:min-h-0"
              aria-label="Search unassigned members"
            />
          </div>

          {/* Filtered results */}
          {filteredUnassigned.length === 0 ? (
            <p className="py-2 text-center text-sm text-slate-400">
              {assignSearch ? "No members match your search." : "All members already have this role."}
            </p>
          ) : (
            <ul className="divide-y divide-slate-50 rounded-xl border border-slate-100">
              {filteredUnassigned.map((member) => {
                const label = getMemberLabel(member);
                const initial = getMemberInitial(member);
                return (
                  <li key={member.userId} className="flex items-center gap-3 px-3 py-3 sm:px-4 sm:py-2.5">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-500 sm:h-7 sm:w-7">
                      {initial}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-800">{label}</p>
                      <p className="text-xs text-slate-400 capitalize">{member.legacyRole}</p>
                    </div>
                    <form action={assignRoleToMemberAction}>
                      <input type="hidden" name="club_id" value={clubId} />
                      <input type="hidden" name="role_id" value={role.id} />
                      <input type="hidden" name="target_user_id" value={member.userId} />
                      <button
                        type="submit"
                        className="flex min-h-10 shrink-0 items-center gap-1 rounded-lg border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-600 transition-colors hover:border-slate-800 hover:bg-slate-900 hover:text-white sm:min-h-7 sm:px-2.5"
                        aria-label={`Assign ${label} to ${role.name}`}
                      >
                        <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
                        </svg>
                        Assign
                      </button>
                    </form>
                  </li>
                );
              })}
            </ul>
          )}

          {unassignedMembers.length > 8 && filteredUnassigned.length === 8 && (
            <p className="mt-2 text-center text-xs text-slate-400">
              Showing 8 results — type to narrow the search.
            </p>
          )}
        </div>
      )}

      {canAssignRoles && unassignedMembers.length === 0 && (
        <p className="text-sm text-slate-400">All club members are assigned to this role.</p>
      )}
    </div>
  );
}
