-- Club-specific teams (definitions + member assignments).
-- Conceptually distinct from committees; same structural pattern as 029.
-- Apply after 029. Idempotent where possible.

-- ─── 1. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.manage_teams', 'Create teams and assign members to them')
on conflict (key) do nothing;

-- ─── 2. Tables ───────────────────────────────────────────────────────────────

create table if not exists public.club_teams (
  id         uuid        primary key default gen_random_uuid(),
  club_id    uuid        not null references public.clubs(id) on delete cascade,
  name       text        not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint club_teams_name_nonempty check (char_length(trim(name)) >= 1)
);

comment on table public.club_teams is 'Named teams within a club (distinct from committees, tags, and RBAC roles).';

create unique index if not exists club_teams_club_name_norm_idx
  on public.club_teams (club_id, lower(trim(name)));

create index if not exists club_teams_club_id_idx
  on public.club_teams (club_id);

drop trigger if exists club_teams_updated_at on public.club_teams;
create trigger club_teams_updated_at
  before update on public.club_teams
  for each row execute function public.touch_updated_at();

create table if not exists public.club_team_members (
  team_id   uuid        not null references public.club_teams(id) on delete cascade,
  user_id   uuid        not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  added_by  uuid        null references public.profiles(id) on delete set null,
  primary key (team_id, user_id)
);

comment on table public.club_team_members is 'Membership in a club team (a user may belong to many teams).';

create index if not exists club_team_members_user_id_idx
  on public.club_team_members (user_id);

-- ─── 3. Triggers ─────────────────────────────────────────────────────────────

create or replace function public.enforce_club_team_member()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_club_id uuid;
begin
  select t.club_id into v_club_id
  from public.club_teams t
  where t.id = new.team_id;

  if v_club_id is null then
    raise exception 'Team not found';
  end if;

  if not exists (
    select 1
    from public.club_members cm
    where cm.club_id = v_club_id
      and cm.user_id = new.user_id
  ) then
    raise exception 'User must be a member of this club to join a team';
  end if;

  return new;
end;
$$;

drop trigger if exists club_team_members_enforce_member on public.club_team_members;
create trigger club_team_members_enforce_member
  before insert or update on public.club_team_members
  for each row execute function public.enforce_club_team_member();

create or replace function public.sync_club_team_members_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_team_members tm
  using public.club_teams t
  where tm.team_id = t.id
    and t.club_id = old.club_id
    and tm.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_team_members on public.club_members;
create trigger club_members_cleanup_team_members
  after delete on public.club_members
  for each row execute function public.sync_club_team_members_on_member_leave();

-- ─── 4. Row-Level Security ───────────────────────────────────────────────────

alter table public.club_teams enable row level security;
alter table public.club_team_members enable row level security;

drop policy if exists "club_teams_select" on public.club_teams;
create policy "club_teams_select"
  on public.club_teams
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_teams.club_id
        and cm.user_id = auth.uid()
    )
  );

drop policy if exists "club_teams_insert" on public.club_teams;
create policy "club_teams_insert"
  on public.club_teams
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_teams')
  );

drop policy if exists "club_teams_update" on public.club_teams;
create policy "club_teams_update"
  on public.club_teams
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_teams')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_teams')
  );

drop policy if exists "club_teams_delete" on public.club_teams;
create policy "club_teams_delete"
  on public.club_teams
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_teams')
  );

drop policy if exists "club_team_members_select" on public.club_team_members;
create policy "club_team_members_select"
  on public.club_team_members
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.club_teams t
      join public.club_members cm on cm.club_id = t.club_id and cm.user_id = auth.uid()
      where t.id = club_team_members.team_id
    )
  );

drop policy if exists "club_team_members_insert" on public.club_team_members;
create policy "club_team_members_insert"
  on public.club_team_members
  for insert
  to authenticated
  with check (
    exists (
      select 1
      from public.club_teams t
      where t.id = team_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_teams')
        )
    )
  );

drop policy if exists "club_team_members_update" on public.club_team_members;
create policy "club_team_members_update"
  on public.club_team_members
  for update
  to authenticated
  using (
    exists (
      select 1
      from public.club_teams t
      where t.id = team_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_teams')
        )
    )
  )
  with check (
    exists (
      select 1
      from public.club_teams t
      where t.id = team_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_teams')
        )
    )
  );

drop policy if exists "club_team_members_delete" on public.club_team_members;
create policy "club_team_members_delete"
  on public.club_team_members
  for delete
  to authenticated
  using (
    exists (
      select 1
      from public.club_teams t
      where t.id = team_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_teams')
        )
    )
  );

-- ─── 5. Update seed_default_club_roles ───────────────────────────────────────

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
    'members.view', 'members.invite', 'members.manage_tags', 'members.manage_committees', 'members.manage_teams',
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

-- ─── 6. Backfill: grant members.manage_teams to President & Officer ──────────

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_teams'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_teams'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
