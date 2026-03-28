-- ─────────────────────────────────────────────────────────────────────────────
-- 017 — RBAC RLS Cleanup & Full Migration
-- Depends on: 013–016 (RBAC schema, backfill, and permission matrix)
--
-- Prior migrations (013–016) were applied manually to the live database.
-- This file documents and finalises the RLS policy migration so the repository
-- accurately reflects the current database permission model.
--
-- Strategy per table:
--   - Drop old officer-only policies.
--   - Re-create them to allow: is_club_officer(…) OR has_club_permission(…).
--   - This preserves access for legacy officer/member clubs while unlocking the
--     same operations for custom RBAC roles with the matching permission.
-- ─────────────────────────────────────────────────────────────────────────────


-- ═══════════════════════════════════════════════════════════════════════════
-- 1. event_reflections
--    Migrated: SELECT (critical — app now fetches reflections for all users
--    and relies on RLS to filter, instead of the application-level officer gate).
-- ═══════════════════════════════════════════════════════════════════════════

-- SELECT: officers OR reflections.create holders
drop policy if exists "event_reflections_select_officer" on public.event_reflections;
drop policy if exists "event_reflections_select_rbac"   on public.event_reflections;
create policy "event_reflections_select_rbac"
on public.event_reflections
for select
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'reflections.create')
      )
  )
);

-- INSERT: officers OR reflections.create holders
drop policy if exists "event_reflections_insert_officer" on public.event_reflections;
drop policy if exists "event_reflections_insert_rbac"   on public.event_reflections;
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
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'reflections.create')
      )
  )
);

-- UPDATE: officers OR reflections.edit holders
drop policy if exists "event_reflections_update_officer" on public.event_reflections;
drop policy if exists "event_reflections_update_rbac"   on public.event_reflections;
create policy "event_reflections_update_rbac"
on public.event_reflections
for update
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'reflections.edit')
      )
  )
)
with check (
  auth.uid() = updated_by
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'reflections.edit')
      )
  )
);

-- DELETE: officers OR reflections.delete holders
drop policy if exists "event_reflections_delete_officer" on public.event_reflections;
drop policy if exists "event_reflections_delete_rbac"   on public.event_reflections;
create policy "event_reflections_delete_rbac"
on public.event_reflections
for delete
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'reflections.delete')
      )
  )
);


-- ═══════════════════════════════════════════════════════════════════════════
-- 2. events
--    Migrated: INSERT/UPDATE/DELETE.  SELECT is unchanged (any club member).
-- ═══════════════════════════════════════════════════════════════════════════

-- INSERT: officers OR events.create holders
drop policy if exists "events_insert_officer" on public.events;
drop policy if exists "events_insert_rbac"    on public.events;
create policy "events_insert_rbac"
on public.events
for insert
to authenticated
with check (
  auth.uid() = created_by
  and (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(auth.uid(), club_id, 'events.create')
  )
);

-- UPDATE: officers OR events.edit holders
drop policy if exists "events_update_officer" on public.events;
drop policy if exists "events_update_rbac"    on public.events;
create policy "events_update_rbac"
on public.events
for update
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(auth.uid(), club_id, 'events.edit')
)
with check (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(auth.uid(), club_id, 'events.edit')
);

-- DELETE: officers OR events.delete holders
drop policy if exists "events_delete_officer" on public.events;
drop policy if exists "events_delete_rbac"    on public.events;
create policy "events_delete_rbac"
on public.events
for delete
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(auth.uid(), club_id, 'events.delete')
);


-- ═══════════════════════════════════════════════════════════════════════════
-- 3. announcements
--    Migrated: INSERT/UPDATE/DELETE.  SELECT unchanged (any club member).
-- ═══════════════════════════════════════════════════════════════════════════

-- INSERT: officers OR announcements.create holders
drop policy if exists "announcements_insert_officer" on public.announcements;
drop policy if exists "announcements_insert_rbac"    on public.announcements;
create policy "announcements_insert_rbac"
on public.announcements
for insert
to authenticated
with check (
  auth.uid() = created_by
  and (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(auth.uid(), club_id, 'announcements.create')
  )
);

-- UPDATE: officers OR announcements.edit holders
drop policy if exists "announcements_update_officer" on public.announcements;
drop policy if exists "announcements_update_rbac"    on public.announcements;
create policy "announcements_update_rbac"
on public.announcements
for update
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(auth.uid(), club_id, 'announcements.edit')
)
with check (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(auth.uid(), club_id, 'announcements.edit')
);

-- DELETE: officers OR announcements.delete holders
drop policy if exists "announcements_delete_officer" on public.announcements;
drop policy if exists "announcements_delete_rbac"    on public.announcements;
create policy "announcements_delete_rbac"
on public.announcements
for delete
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(auth.uid(), club_id, 'announcements.delete')
);


-- ═══════════════════════════════════════════════════════════════════════════
-- 4. event_attendance
--    Migrated: INSERT/DELETE.  SELECT unchanged (any club member).
-- ═══════════════════════════════════════════════════════════════════════════

-- INSERT: officers OR attendance.mark holders
drop policy if exists "event_attendance_insert_officer" on public.event_attendance;
drop policy if exists "event_attendance_insert_rbac"    on public.event_attendance;
create policy "event_attendance_insert_rbac"
on public.event_attendance
for insert
to authenticated
with check (
  auth.uid() = marked_by
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'attendance.mark')
      )
  )
);

-- DELETE (un-mark): officers OR attendance.mark OR attendance.edit holders
drop policy if exists "event_attendance_delete_officer" on public.event_attendance;
drop policy if exists "event_attendance_delete_rbac"    on public.event_attendance;
create policy "event_attendance_delete_rbac"
on public.event_attendance
for delete
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(auth.uid(), e.club_id, 'attendance.mark')
        or public.has_club_permission(auth.uid(), e.club_id, 'attendance.edit')
      )
  )
);


-- ═══════════════════════════════════════════════════════════════════════════
-- 5. clubs — UPDATE policy for club.manage_settings
--    Adds a forward-compatible policy for future "Edit Club Settings" actions.
--    Currently no application action writes directly to clubs; this policy is
--    a guardrail for when that feature is built.
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "clubs_update_officer"        on public.clubs;
drop policy if exists "clubs_update_rbac"           on public.clubs;
create policy "clubs_update_rbac"
on public.clubs
for update
to authenticated
using (
  public.is_club_officer(id, auth.uid())
  or public.has_club_permission(auth.uid(), id, 'club.manage_settings')
)
with check (
  public.is_club_officer(id, auth.uid())
  or public.has_club_permission(auth.uid(), id, 'club.manage_settings')
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Migration summary
-- ─────────────────────────────────────────────────────────────────────────────
-- MIGRATED to RBAC-aware policies (is_club_officer OR has_club_permission):
--   event_reflections  — SELECT, INSERT, UPDATE, DELETE
--   events             — INSERT, UPDATE, DELETE
--   announcements      — INSERT, UPDATE, DELETE
--   event_attendance   — INSERT, DELETE
--   clubs              — UPDATE (forward-compatible)
--
-- UNCHANGED (still legacy-only — acceptable, no RBAC action needed yet):
--   club_members SELECT — any member can read the member list (correct)
--   club_members INSERT — self-insert as member (join flow, correct)
--   clubs SELECT        — any member can read club info (correct)
--   rsvps SELECT/INSERT/UPDATE — any club member can RSVP (correct)
--   profiles SELECT     — any authenticated user can view profiles (correct)
--
-- STILL USES legacy is_club_officer() for some checks but those paths are
-- no longer the primary enforcement layer — the RBAC permission check runs
-- in parallel and grants access to custom role holders with the same effect.
-- ─────────────────────────────────────────────────────────────────────────────
