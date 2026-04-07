-- Club-scoped volunteer hours (log entries; totals computed in app).
-- Apply after 033. Idempotent where possible.

-- ─── 1. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.manage_volunteer_hours', 'Record and edit volunteer hour entries for members')
on conflict (key) do nothing;

-- ─── 2. Table ─────────────────────────────────────────────────────────────────

create table if not exists public.club_member_volunteer_hours (
  id           uuid            primary key default gen_random_uuid(),
  club_id      uuid            not null references public.clubs(id) on delete cascade,
  user_id      uuid            not null references public.profiles(id) on delete cascade,
  hours        numeric(10, 2)  not null,
  note         text            null,
  service_date date            not null default (timezone('utc', now()))::date,
  created_at   timestamptz     not null default now(),
  created_by   uuid            not null references public.profiles(id) on delete restrict,
  updated_at   timestamptz     not null default now(),
  updated_by   uuid            null references public.profiles(id) on delete set null,
  constraint club_member_volunteer_hours_hours_positive
    check (hours > 0 and hours <= 500),
  constraint club_member_volunteer_hours_note_length
    check (note is null or (char_length(trim(note)) >= 1 and char_length(note) <= 500))
);

comment on table public.club_member_volunteer_hours is
  'Per-entry volunteer service hours for a member within a club (not a global profile field).';

create index if not exists club_member_volunteer_hours_club_user_idx
  on public.club_member_volunteer_hours (club_id, user_id);

create index if not exists club_member_volunteer_hours_club_idx
  on public.club_member_volunteer_hours (club_id);

-- ─── 3. Enforce target is (or was) in club: must be current club_members row ───

create or replace function public.enforce_volunteer_hours_club_member()
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
    raise exception 'Volunteer hours can only be recorded for current club members';
  end if;
  return new;
end;
$$;

drop trigger if exists club_member_volunteer_hours_enforce_member
  on public.club_member_volunteer_hours;
create trigger club_member_volunteer_hours_enforce_member
  before insert or update of club_id, user_id on public.club_member_volunteer_hours
  for each row execute function public.enforce_volunteer_hours_club_member();

-- ─── 4. RLS ────────────────────────────────────────────────────────────────────

alter table public.club_member_volunteer_hours enable row level security;

drop policy if exists "club_member_volunteer_hours_select" on public.club_member_volunteer_hours;
create policy "club_member_volunteer_hours_select"
  on public.club_member_volunteer_hours
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_member_volunteer_hours.club_id
        and cm.user_id = auth.uid()
    )
  );

drop policy if exists "club_member_volunteer_hours_insert" on public.club_member_volunteer_hours;
create policy "club_member_volunteer_hours_insert"
  on public.club_member_volunteer_hours
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_volunteer_hours')
  );

drop policy if exists "club_member_volunteer_hours_update" on public.club_member_volunteer_hours;
create policy "club_member_volunteer_hours_update"
  on public.club_member_volunteer_hours
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_volunteer_hours')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_volunteer_hours')
  );

drop policy if exists "club_member_volunteer_hours_delete" on public.club_member_volunteer_hours;
create policy "club_member_volunteer_hours_delete"
  on public.club_member_volunteer_hours
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_volunteer_hours')
  );

-- ─── 5. seed_default_club_roles — grant new permission to Officer ───────────

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
    'members.manage_volunteer_hours',
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

-- ─── 6. Backfill President & Officer ─────────────────────────────────────────

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_volunteer_hours'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_volunteer_hours'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
