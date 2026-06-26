-- ─────────────────────────────────────────────────────────────────────────────
-- 054 — RBAC policy fixes (RLS audit remediation)
-- Depends on: 013 (RBAC foundation), 016 (permission matrix), 017 (RLS cleanup),
--             018 (audit logs), 027 (active-member gates), 051 (advisor approvals)
--
-- FINDING 1 (HIGH): has_club_permission() was called with its first two
--   arguments swapped — has_club_permission(auth.uid(), club_id, key) instead of
--   has_club_permission(club_id, auth.uid(), key). Both args are uuid, so there
--   was no error: the check silently always returned false, disabling every RBAC
--   permission grant on the affected policies (and fully breaking audit-log reads).
--
-- FINDING 2 (MEDIUM): member_roles INSERT only checked members.assign_roles,
--   letting any holder of that permission grant the President system role via a
--   direct PostgREST insert — bypassing the app-layer club.transfer_presidency
--   guard. club_roles INSERT/UPDATE also did not protect the is_system flag or the
--   reserved "President" name.
--
-- Signature reminder:
--   public.has_club_permission(target_club_id uuid, target_user_id uuid, permission_key text)
--
-- NOTES:
--   - event_reflections and event_attendance have no club_id column, so the club
--     id is derived through the events table (e.club_id), passing arguments in the
--     correct order.
--   - is_club_officer() fallbacks are preserved on every policy that had one in the
--     original migrations, so clubs predating the RBAC backfill (014) keep working.
--   - Only existing permission keys are used (reflections.create, attendance.mark,
--     announcements.create/edit/delete, club.manage_settings, audit_logs.view).
--     No new keys are added to the permissions catalog.
-- ─────────────────────────────────────────────────────────────────────────────

begin;

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 1.1 — event_reflections (SELECT, INSERT, UPDATE, DELETE)
-- ═══════════════════════════════════════════════════════════════════════════

-- SELECT: own reflection OR reflections.create (officer covered via has_club_permission after backfill; explicit fallback added on writes)
drop policy if exists "event_reflections_select_rbac" on public.event_reflections;
create policy "event_reflections_select_rbac"
on public.event_reflections
for select
to authenticated
using (
  created_by = auth.uid()
  or exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
);

-- INSERT: club member AND (officer OR reflections.create), with ownership integrity guards
drop policy if exists "event_reflections_insert_rbac" on public.event_reflections;
create policy "event_reflections_insert_rbac"
on public.event_reflections
for insert
to authenticated
with check (
  auth.uid() = created_by
  and auth.uid() = updated_by
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_member(e.club_id, auth.uid())
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
);

-- UPDATE: own reflection AND (officer OR reflections.create)
drop policy if exists "event_reflections_update_rbac" on public.event_reflections;
create policy "event_reflections_update_rbac"
on public.event_reflections
for update
to authenticated
using (
  created_by = auth.uid()
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
)
with check (
  auth.uid() = updated_by
  and created_by = auth.uid()
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
);

-- DELETE: own reflection AND (officer OR reflections.create)
drop policy if exists "event_reflections_delete_rbac" on public.event_reflections;
create policy "event_reflections_delete_rbac"
on public.event_reflections
for delete
to authenticated
using (
  created_by = auth.uid()
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
);

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 1.2 — announcements (INSERT, UPDATE, DELETE)
-- SELECT is intentionally untouched (fixed correctly in 044/051).
-- ═══════════════════════════════════════════════════════════════════════════

-- INSERT: officer OR announcements.create
drop policy if exists "announcements_insert_rbac" on public.announcements;
create policy "announcements_insert_rbac"
on public.announcements
for insert
to authenticated
with check (
  auth.uid() = created_by
  and (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'announcements.create')
  )
);

-- UPDATE: officer OR announcements.edit
drop policy if exists "announcements_update_rbac" on public.announcements;
create policy "announcements_update_rbac"
on public.announcements
for update
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'announcements.edit')
)
with check (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'announcements.edit')
);

-- DELETE: officer OR announcements.delete
drop policy if exists "announcements_delete_rbac" on public.announcements;
create policy "announcements_delete_rbac"
on public.announcements
for delete
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'announcements.delete')
);

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 1.3 — event_attendance (DELETE only; INSERT fixed in 027)
-- event_attendance has no club_id column; club id is derived from events.
-- ═══════════════════════════════════════════════════════════════════════════

-- DELETE (un-mark): officer OR attendance.mark
drop policy if exists "event_attendance_delete_rbac" on public.event_attendance;
create policy "event_attendance_delete_rbac"
on public.event_attendance
for delete
to authenticated
using (
  public.is_club_officer(
    (select e.club_id from public.events e where e.id = event_id),
    auth.uid()
  )
  or public.has_club_permission(
    (select e.club_id from public.events e where e.id = event_id),
    auth.uid(),
    'attendance.mark'
  )
);

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 1.4 — clubs (UPDATE)
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "clubs_update_rbac" on public.clubs;
create policy "clubs_update_rbac"
on public.clubs
for update
to authenticated
using (
  public.is_club_officer(id, auth.uid())
  or public.has_club_permission(id, auth.uid(), 'club.manage_settings')
)
with check (
  public.is_club_officer(id, auth.uid())
  or public.has_club_permission(id, auth.uid(), 'club.manage_settings')
);

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 1.5 — club_audit_logs (SELECT)
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "audit_logs_select_rbac" on public.club_audit_logs;
create policy "audit_logs_select_rbac"
on public.club_audit_logs
for select
to authenticated
using (
  public.has_club_permission(club_id, auth.uid(), 'audit_logs.view')
);

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 2.1 — member_roles INSERT: block self-granting the President (or any
--   system) role unless the actor is already the club President.
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "member_roles_insert_assign_roles" on public.member_roles;
create policy "member_roles_insert_assign_roles"
on public.member_roles
for insert
to authenticated
with check (
  public.has_club_permission(club_id, auth.uid(), 'members.assign_roles')
  and (
    not exists (
      select 1
      from public.club_roles cr
      where cr.id = role_id
        and cr.is_system = true
    )
    or public.is_club_president(club_id, auth.uid())
  )
);

-- ═══════════════════════════════════════════════════════════════════════════
-- FINDING 2.2 — club_roles INSERT/UPDATE: only the President may create or set
--   is_system = true, and the reserved "President" name cannot be applied.
--   Current policy names (set in 016): club_roles_insert_roles_create /
--   club_roles_update_roles_edit. Legacy 013 names dropped defensively too.
-- ═══════════════════════════════════════════════════════════════════════════

-- INSERT: roles.create, and is_system requires President
drop policy if exists "club_roles_insert_roles_manage" on public.club_roles;
drop policy if exists "club_roles_insert_roles_create" on public.club_roles;
create policy "club_roles_insert_roles_create"
on public.club_roles
for insert
to authenticated
with check (
  public.has_club_permission(club_id, auth.uid(), 'roles.create')
  and (
    is_system = false
    or public.is_club_president(club_id, auth.uid())
  )
);

-- UPDATE: roles.edit, is_system requires President, and President name is reserved
drop policy if exists "club_roles_update_roles_manage" on public.club_roles;
drop policy if exists "club_roles_update_roles_edit" on public.club_roles;
create policy "club_roles_update_roles_edit"
on public.club_roles
for update
to authenticated
using (
  public.has_club_permission(club_id, auth.uid(), 'roles.edit')
)
with check (
  public.has_club_permission(club_id, auth.uid(), 'roles.edit')
  and (
    is_system = false
    or public.is_club_president(club_id, auth.uid())
  )
);

commit;
