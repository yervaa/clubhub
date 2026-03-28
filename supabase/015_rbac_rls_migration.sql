-- ClubHub RBAC RLS Migration
--
-- Extends the most critical legacy RLS policies to accept either:
--   (a) the legacy is_club_officer() role, OR
--   (b) the new has_club_permission() RBAC check.
--
-- The OR union means:
--   - All existing officers continue to work without any data migration.
--   - Custom RBAC roles with the relevant permission also work immediately
--     once clubs are backfilled (014_rbac_backfill.sql).
--
-- Legacy policies NOT yet migrated (still officer-only at the DB layer):
--   - clubs_update_officer, clubs_delete_officer (no UI for this yet)
--   - club_members_insert/update (managed via RPCs that check officer internally)
--   - rsvps (all-member access, no officer restriction)
--
-- Apply after 013_rbac_foundation.sql and 014_rbac_backfill.sql.

-- ─── ANNOUNCEMENTS ────────────────────────────────────────────────────────────
-- Was: officer-only insert.
-- Now: officer OR has announcements.create permission.

drop policy if exists "announcements_insert_officer" on public.announcements;
create policy "announcements_insert_officer"
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

-- ─── EVENTS ───────────────────────────────────────────────────────────────────
-- Was: officer-only insert.
-- Now: officer OR has events.create permission.

drop policy if exists "events_insert_officer" on public.events;
create policy "events_insert_officer"
on public.events
for insert
to authenticated
with check (
  auth.uid() = created_by
  and (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'events.create')
  )
);

-- ─── EVENT ATTENDANCE ─────────────────────────────────────────────────────────
-- Was: officer-only insert and delete.
-- Now: officer OR has events.manage_attendance permission.

drop policy if exists "event_attendance_insert_officer" on public.event_attendance;
create policy "event_attendance_insert_officer"
on public.event_attendance
for insert
to authenticated
with check (
  auth.uid() = marked_by
  and exists (
    select 1
    from public.events e
    join public.club_members cm
      on cm.club_id = e.club_id and cm.user_id = user_id
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'events.manage_attendance')
      )
  )
);

drop policy if exists "event_attendance_delete_officer" on public.event_attendance;
create policy "event_attendance_delete_officer"
on public.event_attendance
for delete
to authenticated
using (
  exists (
    select 1
    from public.events e
    join public.club_members cm
      on cm.club_id = e.club_id and cm.user_id = user_id
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'events.manage_attendance')
      )
  )
);

-- ─── EVENT REFLECTIONS ────────────────────────────────────────────────────────
-- Was: officer-only select, insert, and update.
-- Now: officer OR has reflections.create (read + write) / reflections.edit
--      (update only).
--
-- Note: reflections.create covers both read and first write. This matches the
--       application pattern where only officers who can write reflections should
--       see them.

drop policy if exists "event_reflections_select_officer" on public.event_reflections;
create policy "event_reflections_select_officer"
on public.event_reflections
for select
to authenticated
using (
  exists (
    select 1 from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
);

drop policy if exists "event_reflections_insert_officer" on public.event_reflections;
create policy "event_reflections_insert_officer"
on public.event_reflections
for insert
to authenticated
with check (
  auth.uid() = created_by
  and auth.uid() = updated_by
  and exists (
    select 1 from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.create')
      )
  )
);

drop policy if exists "event_reflections_update_officer" on public.event_reflections;
create policy "event_reflections_update_officer"
on public.event_reflections
for update
to authenticated
using (
  exists (
    select 1 from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.edit')
      )
  )
)
with check (
  auth.uid() = updated_by
  and exists (
    select 1 from public.events e
    where e.id = event_id
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'reflections.edit')
      )
  )
);
