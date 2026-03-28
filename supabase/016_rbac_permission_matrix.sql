-- ClubHub RBAC Permission Matrix Update
--
-- Replaces the provisional permission set from 013_rbac_foundation.sql with the
-- finalised 26-key permission matrix. Key structural changes:
--
--   RENAMED: club.transfer_ownership      → club.transfer_presidency
--   REMOVED: events.manage_attendance     (split below)
--   REMOVED: roles.manage                 (split below)
--   ADDED:   attendance.mark, attendance.edit        (new category)
--   ADDED:   reflections.delete
--   ADDED:   roles.create, roles.edit, roles.delete, roles.assign_permissions
--   ADDED:   insights.export
--   ADDED:   audit_logs.view
--
-- BACKFILL IMPACT:
--   • All role_permissions rows are wiped and re-seeded from the new catalog.
--   • System roles (President / Officer / Member) are re-seeded automatically.
--   • CUSTOM roles will lose their permission assignments and must be
--     reconfigured from the UI after this migration runs.
--
-- Apply after 015_rbac_rls_migration.sql.

-- ─── STEP 1: REPLACE PERMISSION CATALOG ──────────────────────────────────────
-- Deleting from permissions cascades to role_permissions (ON DELETE CASCADE),
-- which cleanly removes all permission assignments without touching roles or
-- member_roles.

delete from public.permissions;

insert into public.permissions (key, description) values
  -- Club administration
  ('club.manage_settings',      'Edit club name, description, and join code'),
  ('club.delete',               'Permanently delete the club'),
  ('club.transfer_presidency',  'Transfer the President role to another member'),
  -- Member management
  ('members.view',              'View the member roster and profiles'),
  ('members.invite',            'Share the join code and invite links'),
  ('members.remove',            'Remove members from the club'),
  ('members.assign_roles',      'Assign or revoke RBAC roles for members'),
  -- Role management (split from single roles.manage)
  ('roles.create',              'Create new custom roles'),
  ('roles.edit',                'Edit existing custom role names and descriptions'),
  ('roles.delete',              'Delete custom roles'),
  ('roles.assign_permissions',  'Add or remove permissions on any role'),
  -- Announcements
  ('announcements.create',      'Post new announcements'),
  ('announcements.edit',        'Edit existing announcements'),
  ('announcements.delete',      'Delete announcements'),
  -- Events
  ('events.create',             'Create new events'),
  ('events.edit',               'Edit existing events'),
  ('events.delete',             'Delete events'),
  -- Attendance (formerly events.manage_attendance)
  ('attendance.mark',           'Mark member attendance for an event'),
  ('attendance.edit',           'Correct or unmark attendance records'),
  -- Reflections
  ('reflections.create',        'Write officer reflections for events'),
  ('reflections.edit',          'Edit existing officer reflections'),
  ('reflections.delete',        'Delete officer reflections'),
  -- Insights & analytics
  ('insights.view',             'View the Insights analytics page'),
  ('insights.export',           'Export insights data'),
  -- Audit
  ('audit_logs.view',           'View the club audit log');

-- ─── STEP 2: UPDATE seed_default_club_roles ───────────────────────────────────
-- Replaces the function so new clubs get the correct permission sets.

create or replace function public.seed_default_club_roles(
  p_club_id    uuid,
  p_creator_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_president_id uuid;
  v_officer_id   uuid;
  v_member_id    uuid;
begin
  -- Create system roles.
  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'President', 'Full control over the club', true)
  returning id into v_president_id;

  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Officer', 'Manages events, announcements, and members', true)
  returning id into v_officer_id;

  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Member', 'Standard club member', true)
  returning id into v_member_id;

  -- President: all permissions.
  insert into public.role_permissions (role_id, permission_id)
  select v_president_id, p.id from public.permissions p;

  -- Officer: day-to-day management without admin/destructive powers.
  insert into public.role_permissions (role_id, permission_id)
  select v_officer_id, p.id
  from public.permissions p
  where p.key in (
    'members.view',
    'members.invite',
    'announcements.create',
    'announcements.edit',
    'announcements.delete',
    'events.create',
    'events.edit',
    'events.delete',
    'attendance.mark',
    'attendance.edit',
    'reflections.create',
    'reflections.edit',
    'insights.view'
  );

  -- Member: read-only participation.
  insert into public.role_permissions (role_id, permission_id)
  select v_member_id, p.id
  from public.permissions p
  where p.key in (
    'members.view',
    'insights.view'
  );

  -- Assign creator to President.
  insert into public.member_roles (user_id, club_id, role_id)
  values (p_creator_id, p_club_id, v_president_id);
end;
$$;

revoke all on function public.seed_default_club_roles(uuid, uuid) from public;

-- ─── STEP 3: RE-SEED SYSTEM ROLE PERMISSIONS FOR EXISTING CLUBS ──────────────
-- role_permissions was cleared in step 1. Re-populate the three system roles
-- for every club that already exists.

-- President: all permissions.
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
cross join public.permissions p
where cr.name = 'President'
  and cr.is_system = true;

-- Officer: day-to-day management.
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p
  on p.key in (
    'members.view',
    'members.invite',
    'announcements.create',
    'announcements.edit',
    'announcements.delete',
    'events.create',
    'events.edit',
    'events.delete',
    'attendance.mark',
    'attendance.edit',
    'reflections.create',
    'reflections.edit',
    'insights.view'
  )
where cr.name = 'Officer'
  and cr.is_system = true;

-- Member: read-only.
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p
  on p.key in ('members.view', 'insights.view')
where cr.name = 'Member'
  and cr.is_system = true;

-- ─── STEP 4: UPDATE RLS POLICIES TO USE SPLIT ROLE KEYS ──────────────────────
-- The original policies in 013 used the monolithic 'roles.manage' key.
-- Replace them with the four granular keys.

-- club_roles: INSERT requires roles.create
drop policy if exists "club_roles_insert_roles_manage" on public.club_roles;
create policy "club_roles_insert_roles_create"
on public.club_roles
for insert
to authenticated
with check (public.has_club_permission(club_id, auth.uid(), 'roles.create'));

-- club_roles: UPDATE requires roles.edit
drop policy if exists "club_roles_update_roles_manage" on public.club_roles;
create policy "club_roles_update_roles_edit"
on public.club_roles
for update
to authenticated
using    (public.has_club_permission(club_id, auth.uid(), 'roles.edit'))
with check (public.has_club_permission(club_id, auth.uid(), 'roles.edit'));

-- club_roles: DELETE requires roles.delete
drop policy if exists "club_roles_delete_roles_manage" on public.club_roles;
create policy "club_roles_delete_roles_delete"
on public.club_roles
for delete
to authenticated
using (public.has_club_permission(club_id, auth.uid(), 'roles.delete'));

-- role_permissions: INSERT and DELETE require roles.assign_permissions
drop policy if exists "role_permissions_insert_roles_manage" on public.role_permissions;
create policy "role_permissions_insert_roles_assign"
on public.role_permissions
for insert
to authenticated
with check (
  exists (
    select 1 from public.club_roles cr
    where cr.id = role_id
      and public.has_club_permission(cr.club_id, auth.uid(), 'roles.assign_permissions')
  )
);

drop policy if exists "role_permissions_delete_roles_manage" on public.role_permissions;
create policy "role_permissions_delete_roles_assign"
on public.role_permissions
for delete
to authenticated
using (
  exists (
    select 1 from public.club_roles cr
    where cr.id = role_id
      and public.has_club_permission(cr.club_id, auth.uid(), 'roles.assign_permissions')
  )
);
