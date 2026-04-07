-- Club-scoped member skills & interests (freeform labels; distinct from leadership tags).
-- Apply after 034. Idempotent where possible.

-- ─── 1. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.manage_member_skills', 'Edit skills and interests for any member in the club')
on conflict (key) do nothing;

-- ─── 2. Table ────────────────────────────────────────────────────────────────

create table if not exists public.club_member_skills_interests (
  id         uuid            primary key default gen_random_uuid(),
  club_id    uuid            not null references public.clubs(id) on delete cascade,
  user_id    uuid            not null references public.profiles(id) on delete cascade,
  kind       text            not null,
  label      text            not null,
  created_at timestamptz     not null default now(),
  constraint club_member_skills_interests_kind_check
    check (kind in ('skill', 'interest')),
  constraint club_member_skills_interests_label_length
    check (char_length(trim(label)) >= 1 and char_length(label) <= 80)
);

comment on table public.club_member_skills_interests is
  'Per-club skills and interests for members (preferences / strengths), not RBAC or club tags.';

create unique index if not exists club_member_skills_interests_dedupe_idx
  on public.club_member_skills_interests (club_id, user_id, kind, lower(trim(label)));

create index if not exists club_member_skills_interests_club_user_idx
  on public.club_member_skills_interests (club_id, user_id);

-- ─── 3. Enforce current club membership ─────────────────────────────────────

create or replace function public.enforce_club_member_skills_interests_member()
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
    raise exception 'Skills and interests can only be stored for current club members';
  end if;
  return new;
end;
$$;

drop trigger if exists club_member_skills_interests_enforce_member
  on public.club_member_skills_interests;
create trigger club_member_skills_interests_enforce_member
  before insert or update of club_id, user_id on public.club_member_skills_interests
  for each row execute function public.enforce_club_member_skills_interests_member();

-- ─── 4. Cleanup when member leaves club ─────────────────────────────────────

create or replace function public.sync_club_member_skills_interests_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_member_skills_interests s
  where s.club_id = old.club_id
    and s.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_skills_interests on public.club_members;
create trigger club_members_cleanup_skills_interests
  after delete on public.club_members
  for each row execute function public.sync_club_member_skills_interests_on_member_leave();

-- ─── 5. Row-Level Security ───────────────────────────────────────────────────

alter table public.club_member_skills_interests enable row level security;

drop policy if exists "club_member_skills_interests_select" on public.club_member_skills_interests;
create policy "club_member_skills_interests_select"
  on public.club_member_skills_interests
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_member_skills_interests.club_id
        and cm.user_id = auth.uid()
    )
  );

drop policy if exists "club_member_skills_interests_insert" on public.club_member_skills_interests;
create policy "club_member_skills_interests_insert"
  on public.club_member_skills_interests
  for insert
  to authenticated
  with check (
    (
      user_id = auth.uid()
      and exists (
        select 1 from public.club_members cm
        where cm.club_id = club_member_skills_interests.club_id
          and cm.user_id = auth.uid()
      )
    )
    or public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_skills')
  );

drop policy if exists "club_member_skills_interests_delete" on public.club_member_skills_interests;
create policy "club_member_skills_interests_delete"
  on public.club_member_skills_interests
  for delete
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_member_skills_interests.club_id
        and cm.user_id = auth.uid()
    )
    and (
      club_member_skills_interests.user_id = auth.uid()
      or public.is_club_officer(club_member_skills_interests.club_id, auth.uid())
      or public.has_club_permission(
        club_member_skills_interests.club_id,
        auth.uid(),
        'members.manage_member_skills'
      )
    )
  );

-- ─── 6. seed_default_club_roles — Officer gets new permission ────────────────

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
join public.permissions p on p.key = 'members.manage_member_skills'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_member_skills'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
