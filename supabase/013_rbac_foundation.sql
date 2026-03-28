-- ClubHub RBAC Foundation
-- Adds a flexible, permission-based role system alongside the existing officer/member system.
-- Apply via Supabase SQL editor or CLI after all prior migrations.

-- ─── TABLES ──────────────────────────────────────────────────────────────────

-- Global permission catalog (seeded by migrations, not editable from client).
create table if not exists public.permissions (
  id          uuid primary key default gen_random_uuid(),
  key         text unique not null,
  description text not null default ''
);

-- Per-club roles. is_system = true marks roles created automatically on club creation.
create table if not exists public.club_roles (
  id          uuid primary key default gen_random_uuid(),
  club_id     uuid not null references public.clubs(id) on delete cascade,
  name        text not null,
  description text not null default '',
  is_system   boolean not null default false,
  created_at  timestamptz not null default now()
);

-- Many-to-many: which permissions a role grants.
create table if not exists public.role_permissions (
  role_id       uuid not null references public.club_roles(id) on delete cascade,
  permission_id uuid not null references public.permissions(id) on delete cascade,
  primary key (role_id, permission_id)
);

-- Many-to-many: which RBAC roles a club member holds.
create table if not exists public.member_roles (
  user_id  uuid not null references public.profiles(id) on delete cascade,
  club_id  uuid not null references public.clubs(id)    on delete cascade,
  role_id  uuid not null references public.club_roles(id) on delete cascade,
  primary key (user_id, club_id, role_id)
);

-- ─── INDEXES ─────────────────────────────────────────────────────────────────

create index if not exists idx_club_roles_club_id      on public.club_roles (club_id);
create index if not exists idx_role_permissions_role_id on public.role_permissions (role_id);
create index if not exists idx_member_roles_user_club   on public.member_roles (user_id, club_id);
create index if not exists idx_member_roles_club_id     on public.member_roles (club_id);
create index if not exists idx_permissions_key          on public.permissions (key);

-- ─── SEED: GLOBAL PERMISSIONS ────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('club.manage_settings',      'Edit club name, description, and join code'),
  ('club.delete',               'Permanently delete the club'),
  ('club.transfer_ownership',   'Transfer the President role to another member'),
  ('members.invite',            'Share the join code and invite links'),
  ('members.remove',            'Remove members from the club'),
  ('members.assign_roles',      'Assign or revoke RBAC roles for members'),
  ('members.view',              'View the member roster and profiles'),
  ('events.create',             'Create new events'),
  ('events.edit',               'Edit existing events'),
  ('events.delete',             'Delete events'),
  ('events.manage_attendance',  'Mark and unmark member attendance'),
  ('announcements.create',      'Post new announcements'),
  ('announcements.edit',        'Edit existing announcements'),
  ('announcements.delete',      'Delete announcements'),
  ('reflections.create',        'Write officer reflections for events'),
  ('reflections.edit',          'Edit existing officer reflections'),
  ('insights.view',             'View the Insights analytics page'),
  ('roles.manage',              'Create, edit, and delete custom roles')
on conflict (key) do nothing;

-- ─── HELPER: PERMISSION CHECK ─────────────────────────────────────────────────
-- security definer so it can bypass RLS when called from within other policies.

create or replace function public.has_club_permission(
  target_club_id  uuid,
  target_user_id  uuid,
  permission_key  text
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.member_roles  mr
    join public.role_permissions rp on rp.role_id       = mr.role_id
    join public.permissions      p  on p.id             = rp.permission_id
    where mr.user_id  = target_user_id
      and mr.club_id  = target_club_id
      and p.key       = permission_key
  );
$$;

revoke all on function public.has_club_permission(uuid, uuid, text) from public;
grant execute on function public.has_club_permission(uuid, uuid, text) to authenticated;

-- ─── HELPER: FULL PERMISSION LIST ────────────────────────────────────────────

create or replace function public.get_user_permissions(
  target_user_id  uuid,
  target_club_id  uuid
)
returns table (permission_key text)
language sql
stable
security definer
set search_path = public
as $$
  select distinct p.key
  from public.member_roles     mr
  join public.role_permissions rp on rp.role_id = mr.role_id
  join public.permissions      p  on p.id       = rp.permission_id
  where mr.user_id = target_user_id
    and mr.club_id = target_club_id;
$$;

revoke all on function public.get_user_permissions(uuid, uuid) from public;
grant execute on function public.get_user_permissions(uuid, uuid) to authenticated;

-- ─── HELPER: PRESIDENT CHECK ─────────────────────────────────────────────────

create or replace function public.is_club_president(
  target_club_id uuid,
  target_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.member_roles mr
    join public.club_roles   cr on cr.id = mr.role_id
    where mr.user_id = target_user_id
      and mr.club_id = target_club_id
      and cr.name    = 'President'
      and cr.is_system = true
  );
$$;

revoke all on function public.is_club_president(uuid, uuid) from public;
grant execute on function public.is_club_president(uuid, uuid) to authenticated;

-- ─── SEED DEFAULT ROLES ON CLUB CREATION ─────────────────────────────────────
-- Creates President / Officer / Member roles for a club and assigns the creator
-- to President. Called at the end of create_club_with_creator_membership.

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
  -- President ─ full control
  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'President', 'Full control over the club', true)
  returning id into v_president_id;

  -- Officer ─ day-to-day management
  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Officer', 'Manages events, announcements, and members', true)
  returning id into v_officer_id;

  -- Member ─ read-only participation
  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Member', 'Standard club member', true)
  returning id into v_member_id;

  -- President gets every permission
  insert into public.role_permissions (role_id, permission_id)
  select v_president_id, p.id from public.permissions p;

  -- Officer permissions
  insert into public.role_permissions (role_id, permission_id)
  select v_officer_id, p.id
  from public.permissions p
  where p.key in (
    'members.view',
    'members.invite',
    'events.create',
    'events.edit',
    'announcements.create',
    'announcements.edit',
    'reflections.create',
    'reflections.edit',
    'insights.view'
  );

  -- Member permissions
  insert into public.role_permissions (role_id, permission_id)
  select v_member_id, p.id
  from public.permissions p
  where p.key in ('members.view', 'insights.view');

  -- Assign creator to President
  insert into public.member_roles (user_id, club_id, role_id)
  values (p_creator_id, p_club_id, v_president_id);
end;
$$;

-- Not callable from client — only invoked internally by create_club_with_creator_membership.
revoke all on function public.seed_default_club_roles(uuid, uuid) from public;

-- ─── UPDATE CLUB CREATION FUNCTION ───────────────────────────────────────────
-- Extends the existing atomic creation function to seed RBAC roles.

create or replace function public.create_club_with_creator_membership(
  target_club_id    uuid,
  target_name       text,
  target_description text,
  target_join_code  text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'not_authenticated';
  end if;

  insert into public.clubs (id, name, description, join_code, created_by)
  values (
    target_club_id,
    target_name,
    target_description,
    upper(trim(target_join_code)),
    auth.uid()
  );

  -- Legacy role (keeps existing officer/member system intact)
  insert into public.club_members (club_id, user_id, role)
  values (target_club_id, auth.uid(), 'officer')
  on conflict (club_id, user_id) do update set role = 'officer';

  -- RBAC roles (new system)
  perform public.seed_default_club_roles(target_club_id, auth.uid());

  return target_club_id;
end;
$$;

revoke all on function public.create_club_with_creator_membership(uuid, text, text, text) from public;
grant execute on function public.create_club_with_creator_membership(uuid, text, text, text) to authenticated;

-- ─── PROTECTION TRIGGERS ─────────────────────────────────────────────────────

-- Prevent deletion of system roles (President / Officer / Member).
create or replace function public.prevent_deleting_system_roles()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.is_system = true then
    raise exception 'System roles (President, Officer, Member) cannot be deleted';
  end if;
  return old;
end;
$$;

drop trigger if exists prevent_deleting_system_roles on public.club_roles;
create trigger prevent_deleting_system_roles
before delete on public.club_roles
for each row execute function public.prevent_deleting_system_roles();

-- Prevent removing the last President from any club.
create or replace function public.prevent_removing_last_president()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role_name        text;
  v_remaining_presidents integer;
begin
  select cr.name into v_role_name
  from public.club_roles cr
  where cr.id = old.role_id;

  if v_role_name = 'President' then
    select count(*) into v_remaining_presidents
    from public.member_roles mr
    join public.club_roles   cr on cr.id = mr.role_id
    where mr.club_id   = old.club_id
      and cr.name      = 'President'
      and mr.user_id  <> old.user_id;

    if v_remaining_presidents = 0 then
      raise exception 'Cannot remove the last President from a club';
    end if;
  end if;

  return old;
end;
$$;

drop trigger if exists prevent_removing_last_president on public.member_roles;
create trigger prevent_removing_last_president
before delete on public.member_roles
for each row execute function public.prevent_removing_last_president();

-- ─── ROW-LEVEL SECURITY ───────────────────────────────────────────────────────

alter table public.permissions    enable row level security;
alter table public.club_roles     enable row level security;
alter table public.role_permissions enable row level security;
alter table public.member_roles   enable row level security;

-- permissions: readable by all authenticated users (global catalog).
drop policy if exists "permissions_select_authenticated" on public.permissions;
create policy "permissions_select_authenticated"
on public.permissions
for select
to authenticated
using (true);

-- club_roles: club members can read; roles.manage holders can write.
drop policy if exists "club_roles_select_member" on public.club_roles;
create policy "club_roles_select_member"
on public.club_roles
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

drop policy if exists "club_roles_insert_roles_manage" on public.club_roles;
create policy "club_roles_insert_roles_manage"
on public.club_roles
for insert
to authenticated
with check (public.has_club_permission(club_id, auth.uid(), 'roles.manage'));

drop policy if exists "club_roles_update_roles_manage" on public.club_roles;
create policy "club_roles_update_roles_manage"
on public.club_roles
for update
to authenticated
using    (public.has_club_permission(club_id, auth.uid(), 'roles.manage'))
with check (public.has_club_permission(club_id, auth.uid(), 'roles.manage'));

drop policy if exists "club_roles_delete_roles_manage" on public.club_roles;
create policy "club_roles_delete_roles_manage"
on public.club_roles
for delete
to authenticated
using (public.has_club_permission(club_id, auth.uid(), 'roles.manage'));

-- role_permissions: readable by club members; writable by roles.manage holders.
drop policy if exists "role_permissions_select_member" on public.role_permissions;
create policy "role_permissions_select_member"
on public.role_permissions
for select
to authenticated
using (
  exists (
    select 1 from public.club_roles cr
    where cr.id = role_id
      and public.is_club_member(cr.club_id, auth.uid())
  )
);

drop policy if exists "role_permissions_insert_roles_manage" on public.role_permissions;
create policy "role_permissions_insert_roles_manage"
on public.role_permissions
for insert
to authenticated
with check (
  exists (
    select 1 from public.club_roles cr
    where cr.id = role_id
      and public.has_club_permission(cr.club_id, auth.uid(), 'roles.manage')
  )
);

drop policy if exists "role_permissions_delete_roles_manage" on public.role_permissions;
create policy "role_permissions_delete_roles_manage"
on public.role_permissions
for delete
to authenticated
using (
  exists (
    select 1 from public.club_roles cr
    where cr.id = role_id
      and public.has_club_permission(cr.club_id, auth.uid(), 'roles.manage')
  )
);

-- member_roles: club members can read; members.assign_roles holders can manage.
drop policy if exists "member_roles_select_member" on public.member_roles;
create policy "member_roles_select_member"
on public.member_roles
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

drop policy if exists "member_roles_insert_assign_roles" on public.member_roles;
create policy "member_roles_insert_assign_roles"
on public.member_roles
for insert
to authenticated
with check (public.has_club_permission(club_id, auth.uid(), 'members.assign_roles'));

drop policy if exists "member_roles_delete_assign_roles" on public.member_roles;
create policy "member_roles_delete_assign_roles"
on public.member_roles
for delete
to authenticated
using (public.has_club_permission(club_id, auth.uid(), 'members.assign_roles'));
