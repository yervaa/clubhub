-- Member list import (CSV): permission + SECURITY DEFINER RPCs for email resolution
-- and batched membership inserts. Apply after 038.
--
-- v1: adds existing profiles as club members (role = member, membership_status = active).
--     No placeholder users or invites.

insert into public.permissions (key, description) values
  ('members.import_roster', 'Import existing users into the club from a validated CSV (leadership only)')
on conflict (key) do nothing;

-- seed_default_club_roles — Officer gets import (alongside export and other officer perms)

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
  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'President', 'Full control over the club', true)
  returning id into v_president_id;

  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Officer', 'Manages events, announcements, and members', true)
  returning id into v_officer_id;

  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Member', 'Standard club member', true)
  returning id into v_member_id;

  insert into public.role_permissions (role_id, permission_id)
  select v_president_id, p.id from public.permissions p;

  insert into public.role_permissions (role_id, permission_id)
  select v_officer_id, p.id
  from public.permissions p
  where p.key in (
    'members.view', 'members.invite', 'members.review_join_requests',
    'members.manage_tags', 'members.manage_committees', 'members.manage_teams',
    'members.manage_volunteer_hours', 'members.manage_member_skills',
    'members.manage_member_availability', 'members.manage_officer_notes',
    'members.export_roster', 'members.import_roster',
    'announcements.create', 'announcements.edit', 'announcements.delete',
    'events.create', 'events.edit', 'events.delete',
    'attendance.mark', 'attendance.edit',
    'reflections.create', 'reflections.edit',
    'insights.view',
    'tasks.view', 'tasks.create', 'tasks.edit', 'tasks.assign', 'tasks.complete'
  );

  insert into public.role_permissions (role_id, permission_id)
  select v_member_id, p.id
  from public.permissions p
  where p.key in (
    'members.view',
    'insights.view',
    'tasks.view', 'tasks.complete'
  );

  insert into public.member_roles (user_id, club_id, role_id)
  values (p_creator_id, p_club_id, v_president_id);
end;
$$;

revoke all on function public.seed_default_club_roles(uuid, uuid) from public;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.import_roster'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.import_roster'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;

-- ─── Helpers: caller may import if active officer OR holds members.import_roster ─

create or replace function public.can_import_club_member_list(
  p_club_id uuid,
  p_actor_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    public.is_club_member(p_club_id, p_actor_id)
    and (
      public.has_club_permission(p_club_id, p_actor_id, 'members.import_roster')
      or public.is_club_officer(p_club_id, p_actor_id)
    );
$$;

revoke all on function public.can_import_club_member_list(uuid, uuid) from public;
grant execute on function public.can_import_club_member_list(uuid, uuid) to authenticated;

-- ─── Resolve normalized emails to profiles (bypasses clubmate-only profile RLS) ─

create or replace function public.lookup_profiles_for_member_import(
  p_club_id uuid,
  p_emails  text[]
)
returns table (
  norm_email text,
  user_id    uuid,
  full_name  text
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor uuid := auth.uid();
begin
  if v_actor is null then
    raise exception 'not authenticated';
  end if;

  if exists (
    select 1 from public.clubs c
    where c.id = p_club_id and c.status = 'archived'
  ) then
    raise exception 'club archived';
  end if;

  if not public.can_import_club_member_list(p_club_id, v_actor) then
    raise exception 'permission denied';
  end if;

  if coalesce(array_length(p_emails, 1), 0) > 400 then
    raise exception 'too many rows';
  end if;

  return query
  select
    lower(trim(p.email)) as norm_email,
    p.id as user_id,
    p.full_name
  from public.profiles p
  where exists (
    select 1
    from unnest(p_emails) as u(email_txt)
    where trim(u.email_txt) <> ''
      and lower(trim(p.email)) = lower(trim(u.email_txt))
  );
end;
$$;

revoke all on function public.lookup_profiles_for_member_import(uuid, text[]) from public;
grant execute on function public.lookup_profiles_for_member_import(uuid, text[]) to authenticated;

-- ─── Commit import: ordered emails, first occurrence wins; partial adds with counts ─

create or replace function public.commit_club_member_import(
  p_club_id uuid,
  p_emails  text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor       uuid := auth.uid();
  v_email       text;
  v_norm        text;
  v_seen        text[] := array[]::text[];
  v_uid         uuid;
  n_added       int := 0;
  n_dup_file    int := 0;
  n_no_profile  int := 0;
  n_already     int := 0;
begin
  if v_actor is null then
    return jsonb_build_object('ok', false, 'error', 'not_authenticated');
  end if;

  if exists (
    select 1 from public.clubs c
    where c.id = p_club_id and c.status = 'archived'
  ) then
    return jsonb_build_object('ok', false, 'error', 'club_archived');
  end if;

  if not public.can_import_club_member_list(p_club_id, v_actor) then
    return jsonb_build_object('ok', false, 'error', 'permission_denied');
  end if;

  if coalesce(array_length(p_emails, 1), 0) > 400 then
    return jsonb_build_object('ok', false, 'error', 'too_many_rows');
  end if;

  foreach v_email in array p_emails
  loop
    v_norm := lower(trim(v_email));
    if v_norm = '' then
      continue;
    end if;
    if v_norm = any(v_seen) then
      n_dup_file := n_dup_file + 1;
      continue;
    end if;
    v_seen := array_append(v_seen, v_norm);

    select p.id into v_uid
    from public.profiles p
    where lower(trim(p.email)) = v_norm
    limit 1;

    if v_uid is null then
      n_no_profile := n_no_profile + 1;
      continue;
    end if;

    if exists (
      select 1
      from public.club_members cm
      where cm.club_id = p_club_id
        and cm.user_id = v_uid
    ) then
      n_already := n_already + 1;
      continue;
    end if;

    insert into public.club_members (club_id, user_id, role, membership_status)
    values (p_club_id, v_uid, 'member', 'active');

    n_added := n_added + 1;
  end loop;

  return jsonb_build_object(
    'ok', true,
    'added', n_added,
    'skipped_duplicate_in_file', n_dup_file,
    'skipped_no_profile', n_no_profile,
    'skipped_already_member', n_already
  );
end;
$$;

revoke all on function public.commit_club_member_import(uuid, text[]) from public;
grant execute on function public.commit_club_member_import(uuid, text[]) to authenticated;

comment on function public.lookup_profiles_for_member_import(uuid, text[]) is
  'Leadership-only: map normalized emails to profile ids for CSV import preview (bypasses profile RLS).';

comment on function public.commit_club_member_import(uuid, text[]) is
  'Leadership-only: insert club_members rows for resolved emails; skips unknown users and existing members.';
