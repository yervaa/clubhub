import Link from "next/link";
import type { ClubRole, MemberWithRoles } from "@/lib/rbac/role-actions";
import type { PermissionKey } from "@/lib/rbac/permissions";
import { RolePermissionEditor } from "@/components/ui/role-permission-editor";
import { createCustomRoleAction } from "@/app/(app)/clubs/rbac-actions";

type ClubSettingsSectionProps = {
  clubId: string;
  roles: ClubRole[];
  memberCountByRole: Record<string, number>;
  selectedRole: ClubRole | null;
  allPermissionKeys: PermissionKey[];
  isPresident: boolean;
  assignedMembers: MemberWithRoles[];
  unassignedMembers: MemberWithRoles[];
  mode?: string;
  success?: string;
  error?: string;
};

export function ClubSettingsSection({
  clubId,
  roles,
  memberCountByRole,
  selectedRole,
  allPermissionKeys,
  isPresident,
  assignedMembers,
  unassignedMembers,
  mode,
  success,
  error,
}: ClubSettingsSectionProps) {
  const systemRoles = roles.filter((r) => r.isSystem);
  const customRoles = roles.filter((r) => !r.isSystem);
  const isCreating = mode === "create";

  return (
    <section className="space-y-6">

      {/* Page header */}
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-violet-50 p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Club Settings</p>
          <h1 className="section-title mt-3 text-3xl md:text-4xl">Roles &amp; Permissions</h1>
          <p className="section-subtitle mt-4 max-w-2xl text-lg text-slate-700">
            {isPresident
              ? "Control who can do what in your club. Create custom roles and fine-tune permissions for each one."
              : "See how roles and permissions are configured for this club."}
          </p>

          <div className="mt-6 flex flex-wrap items-center gap-6">
            <div>
              <p className="text-2xl font-bold text-slate-900">{roles.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Roles</p>
            </div>
            <div className="h-8 w-px bg-slate-200" />
            <div>
              <p className="text-2xl font-bold text-slate-900">{customRoles.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Custom</p>
            </div>
            <div className="h-8 w-px bg-slate-200" />
            <div>
              <p className="text-2xl font-bold text-slate-900">{allPermissionKeys.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Permissions</p>
            </div>
          </div>

          {!isPresident && (
            <div className="mt-6 inline-flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm text-amber-800">
              <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M12 3a9 9 0 100 18A9 9 0 0012 3z" />
              </svg>
              You have read-only access. Only Presidents can edit roles and permissions.
            </div>
          )}
        </div>
      </header>

      {/* Status banners */}
      {success && (
        <div className="flex items-center gap-3 rounded-lg border border-emerald-200 bg-emerald-50 px-5 py-3.5 text-sm font-medium text-emerald-800">
          <svg className="h-4.5 w-4.5 flex-shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {decodeURIComponent(success.replace(/\+/g, " "))}
        </div>
      )}
      {error && (
        <div className="flex items-center gap-3 rounded-lg border border-red-200 bg-red-50 px-5 py-3.5 text-sm font-medium text-red-800">
          <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M12 3a9 9 0 100 18A9 9 0 0012 3z" />
          </svg>
          {decodeURIComponent(error.replace(/\+/g, " "))}
        </div>
      )}

      {/* Main editor area: role list (left) + editor (right) */}
      <div className="grid gap-5 lg:grid-cols-[280px_1fr]">

        {/* ── Left: Role list ─────────────────────────────────────────────────── */}
        <aside className="flex flex-col gap-3">
          <div className="card-surface p-3">

            {/* System roles */}
            <div className="px-1 pb-1 pt-0.5">
              <p className="section-kicker text-[0.7rem] text-slate-400">System Roles</p>
            </div>
            <ul className="space-y-0.5" role="list">
              {systemRoles.map((role) => (
                <li key={role.id}>
                  <RoleListItem
                    role={role}
                    memberCount={memberCountByRole[role.id] ?? 0}
                    isActive={!isCreating && selectedRole?.id === role.id}
                    href={`/clubs/${clubId}/settings?roleId=${role.id}`}
                  />
                </li>
              ))}
            </ul>

            {/* Custom roles */}
            {customRoles.length > 0 && (
              <>
                <div className="mt-4 px-1 pb-1">
                  <p className="section-kicker text-[0.7rem] text-slate-400">Custom Roles</p>
                </div>
                <ul className="space-y-0.5" role="list">
                  {customRoles.map((role) => (
                    <li key={role.id}>
                      <RoleListItem
                        role={role}
                        memberCount={memberCountByRole[role.id] ?? 0}
                        isActive={!isCreating && selectedRole?.id === role.id}
                        href={`/clubs/${clubId}/settings?roleId=${role.id}`}
                      />
                    </li>
                  ))}
                </ul>
              </>
            )}

            {/* New role button — Presidents with roles.create */}
            {isPresident && (
              <div className="mt-3 border-t border-slate-100 pt-3">
                <Link
                  href={`/clubs/${clubId}/settings?mode=create`}
                  className={`flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-semibold transition-colors ${
                    isCreating
                      ? "bg-slate-900 text-white"
                      : "text-slate-500 hover:bg-slate-50 hover:text-slate-800"
                  }`}
                >
                  <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                  </svg>
                  New Role
                </Link>
              </div>
            )}
          </div>
        </aside>

        {/* ── Right: Editor ───────────────────────────────────────────────────── */}
        <div>
          {isCreating ? (
            <CreateRolePanel clubId={clubId} />
          ) : selectedRole ? (
            <RolePermissionEditor
              key={selectedRole.id}
              role={selectedRole}
              allPermissionKeys={allPermissionKeys}
              clubId={clubId}
              isPresident={isPresident}
              assignedMembers={assignedMembers}
              unassignedMembers={unassignedMembers}
            />
          ) : (
            <div className="empty-state">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100">
                <svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <p className="empty-state-title">No roles yet</p>
              <p className="empty-state-copy">Select a role from the left to view or edit it.</p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

// ─── Role list item (server-rendered) ────────────────────────────────────────

type RoleListItemProps = {
  role: ClubRole;
  memberCount: number;
  isActive: boolean;
  href: string;
};

function RoleListItem({ role, memberCount, isActive, href }: RoleListItemProps) {
  const isPresident = role.name === "President" && role.isSystem;
  const permCount = role.permissions.length;

  return (
    <Link
      href={href}
      aria-current={isActive ? "true" : undefined}
      className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors ${
        isActive
          ? "bg-slate-900 text-white"
          : "text-slate-700 hover:bg-slate-50"
      }`}
    >
      {/* Role colour dot */}
      <span
        className={`flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full text-xs font-bold ${
          isActive
            ? "bg-white/15 text-white"
            : isPresident
              ? "bg-violet-100 text-violet-700"
              : role.isSystem
                ? "bg-blue-100 text-blue-700"
                : "bg-emerald-100 text-emerald-700"
        }`}
      >
        {role.name.slice(0, 1).toUpperCase()}
      </span>

      <div className="min-w-0 flex-1">
        <p className={`truncate text-sm font-semibold leading-tight ${isActive ? "text-white" : "text-slate-900"}`}>
          {role.name}
        </p>
        <p className={`mt-0.5 text-xs leading-tight ${isActive ? "text-white/60" : "text-slate-500"}`}>
          {isPresident ? "All permissions" : `${permCount} perm${permCount !== 1 ? "s" : ""}`}
          {" · "}
          {memberCount} {memberCount === 1 ? "member" : "members"}
        </p>
      </div>

      {role.isSystem && (
        <span className={`flex-shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${isActive ? "bg-white/15 text-white/80" : "bg-slate-100 text-slate-400"}`}>
          sys
        </span>
      )}
    </Link>
  );
}

// ─── Create role panel (server-rendered form) ─────────────────────────────────

function CreateRolePanel({ clubId }: { clubId: string }) {
  return (
    <div className="card-surface p-6 md:p-8">
      <div className="mb-6">
        <p className="section-kicker">New Role</p>
        <h2 className="section-title mt-2 text-xl">Create a custom role</h2>
        <p className="section-subtitle mt-1">
          Add a new role with a custom set of permissions. You can adjust its permissions after saving.
        </p>
      </div>

      <form action={createCustomRoleAction} className="space-y-5">
        <input type="hidden" name="club_id" value={clubId} />

        <div className="space-y-1.5">
          <label htmlFor="role-name" className="block text-sm font-semibold text-slate-700">
            Role name <span className="text-red-500">*</span>
          </label>
          <input
            id="role-name"
            name="name"
            type="text"
            required
            maxLength={50}
            placeholder="e.g. Social Media Lead"
            className="input-control"
            autoFocus
          />
          <p className="text-xs text-slate-400">Max 50 characters.</p>
        </div>

        <div className="space-y-1.5">
          <label htmlFor="role-desc" className="block text-sm font-semibold text-slate-700">
            Description
          </label>
          <input
            id="role-desc"
            name="description"
            type="text"
            maxLength={200}
            placeholder="Short description of what this role does"
            className="input-control"
          />
          <p className="text-xs text-slate-400">Optional. Max 200 characters.</p>
        </div>

        <div className="flex flex-col gap-3 border-t border-slate-100 pt-5 sm:flex-row sm:items-center">
          <button type="submit" className="btn-primary px-5 py-2.5">
            Create Role
          </button>
          <Link
            href={`/clubs/${clubId}/settings`}
            className="btn-secondary px-5 py-2.5 text-center"
          >
            Cancel
          </Link>
        </div>
      </form>
    </div>
  );
}
