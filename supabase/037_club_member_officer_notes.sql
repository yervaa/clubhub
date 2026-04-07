-- Officer-only internal notes per club member (not visible to regular members via RLS).
-- Apply after 036. Idempotent where possible.

-- ─── 1. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.manage_officer_notes', 'View and edit internal officer notes about members')
on conflict (key) do nothing;

-- ─── 2. Table (single current note per member per club; extend later with history if needed) ─

create table if not exists public.club_member_officer_notes (
  club_id    uuid            not null references public.clubs(id) on delete cascade,
  user_id    uuid            not null references public.profiles(id) on delete cascade,
  body       text            not null default '',
  updated_at timestamptz     not null default now(),
  updated_by uuid            null references public.profiles(id) on delete set null,
  primary key (club_id, user_id),
  constraint club_member_officer_notes_body_max
    check (char_length(body) <= 4000)
);

comment on table public.club_member_officer_notes is
  'Leadership-only operational notes about a member within a club. Never exposed to non-authorized members.';

create index if not exists club_member_officer_notes_club_idx
  on public.club_member_officer_notes (club_id);

-- ─── 3. Enforce target is a current club member ──────────────────────────────

create or replace function public.enforce_club_member_officer_notes_member()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (
    select 1
    from public.club_members cm
    where cm.club_id = new.club_id
      and cm.user_id = new.user_id
  ) then
    raise exception 'Officer notes can only be stored for current club members';
  end if;
  return new;
end;
$$;

drop trigger if exists club_member_officer_notes_enforce_member
  on public.club_member_officer_notes;
create trigger club_member_officer_notes_enforce_member
  before insert or update of club_id, user_id on public.club_member_officer_notes
  for each row execute function public.enforce_club_member_officer_notes_member();

-- ─── 4. Cleanup when member leaves club ──────────────────────────────────────

create or replace function public.sync_club_member_officer_notes_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_member_officer_notes n
  where n.club_id = old.club_id
    and n.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_officer_notes on public.club_members;
create trigger club_members_cleanup_officer_notes
  after delete on public.club_members
  for each row execute function public.sync_club_member_officer_notes_on_member_leave();

-- ─── 5. Row-Level Security (leadership / permission only — never members) ───

alter table public.club_member_officer_notes enable row level security;

drop policy if exists "club_member_officer_notes_select" on public.club_member_officer_notes;
create policy "club_member_officer_notes_select"
  on public.club_member_officer_notes
  for select
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_officer_notes')
  );

drop policy if exists "club_member_officer_notes_insert" on public.club_member_officer_notes;
create policy "club_member_officer_notes_insert"
  on public.club_member_officer_notes
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_officer_notes')
  );

drop policy if exists "club_member_officer_notes_update" on public.club_member_officer_notes;
create policy "club_member_officer_notes_update"
  on public.club_member_officer_notes
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_officer_notes')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_officer_notes')
  );

drop policy if exists "club_member_officer_notes_delete" on public.club_member_officer_notes;
create policy "club_member_officer_notes_delete"
  on public.club_member_officer_notes
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_officer_notes')
  );

-- ─── 6. seed_default_club_roles ──────────────────────────────────────────────

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
    'tasks.view',
    'tasks.complete'
  );

  insert into public.member_roles (user_id, club_id, role_id)
  values (p_creator_id, p_club_id, v_president_id);
end;
$$;

revoke all on function public.seed_default_club_roles(uuid, uuid) from public;

-- ─── 7. Backfill President & Officer ─────────────────────────────────────────

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_officer_notes'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_officer_notes'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
