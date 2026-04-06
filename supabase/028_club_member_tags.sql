-- Club-specific member tags (normalized: definitions + assignments).
-- Apply after 020 (tasks / seed_default_club_roles) and 027 (alumni).
-- Idempotent where possible.

-- ─── 1. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.manage_tags', 'Create club tags and assign them to members')
on conflict (key) do nothing;

-- ─── 2. Tables ───────────────────────────────────────────────────────────────

create table if not exists public.club_member_tags (
  id         uuid        primary key default gen_random_uuid(),
  club_id    uuid        not null references public.clubs(id) on delete cascade,
  name       text        not null,
  created_at timestamptz not null default now(),
  constraint club_member_tags_name_nonempty check (char_length(trim(name)) >= 1)
);

comment on table public.club_member_tags is 'Club-defined labels for organizing members (not RBAC roles).';

create unique index if not exists club_member_tags_club_name_norm_idx
  on public.club_member_tags (club_id, lower(trim(name)));

create index if not exists club_member_tags_club_id_idx
  on public.club_member_tags (club_id);

create table if not exists public.club_member_tag_assignments (
  tag_id      uuid        not null references public.club_member_tags(id) on delete cascade,
  user_id     uuid        not null references public.profiles(id) on delete cascade,
  assigned_at timestamptz not null default now(),
  assigned_by uuid        null references public.profiles(id) on delete set null,
  primary key (tag_id, user_id)
);

comment on table public.club_member_tag_assignments is 'Which members carry which club tags.';

create index if not exists club_member_tag_assignments_user_id_idx
  on public.club_member_tag_assignments (user_id);

-- ─── 3. Triggers ─────────────────────────────────────────────────────────────

create or replace function public.enforce_club_member_tag_assignment()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_club_id uuid;
begin
  select t.club_id into v_club_id
  from public.club_member_tags t
  where t.id = new.tag_id;

  if v_club_id is null then
    raise exception 'Tag not found';
  end if;

  if not exists (
    select 1
    from public.club_members cm
    where cm.club_id = v_club_id
      and cm.user_id = new.user_id
  ) then
    raise exception 'User must be a member of this club to receive a tag';
  end if;

  return new;
end;
$$;

drop trigger if exists club_member_tag_assignments_enforce_member on public.club_member_tag_assignments;
create trigger club_member_tag_assignments_enforce_member
  before insert or update on public.club_member_tag_assignments
  for each row execute function public.enforce_club_member_tag_assignment();

create or replace function public.sync_club_member_tag_assignments_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_member_tag_assignments a
  using public.club_member_tags t
  where a.tag_id = t.id
    and t.club_id = old.club_id
    and a.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_tag_assignments on public.club_members;
create trigger club_members_cleanup_tag_assignments
  after delete on public.club_members
  for each row execute function public.sync_club_member_tag_assignments_on_member_leave();

-- ─── 4. Row-Level Security ─────────────────────────────────────────────────────

alter table public.club_member_tags enable row level security;
alter table public.club_member_tag_assignments enable row level security;

-- Tags: any club member can read definitions.
drop policy if exists "club_member_tags_select" on public.club_member_tags;
create policy "club_member_tags_select"
  on public.club_member_tags
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_member_tags.club_id
        and cm.user_id = auth.uid()
    )
  );

drop policy if exists "club_member_tags_insert" on public.club_member_tags;
create policy "club_member_tags_insert"
  on public.club_member_tags
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_tags')
  );

drop policy if exists "club_member_tags_update" on public.club_member_tags;
create policy "club_member_tags_update"
  on public.club_member_tags
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_tags')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_tags')
  );

drop policy if exists "club_member_tags_delete" on public.club_member_tags;
create policy "club_member_tags_delete"
  on public.club_member_tags
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_tags')
  );

-- Assignments: members can see assignments in their club.
drop policy if exists "club_member_tag_assignments_select" on public.club_member_tag_assignments;
create policy "club_member_tag_assignments_select"
  on public.club_member_tag_assignments
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.club_member_tags t
      join public.club_members cm on cm.club_id = t.club_id and cm.user_id = auth.uid()
      where t.id = club_member_tag_assignments.tag_id
    )
  );

drop policy if exists "club_member_tag_assignments_insert" on public.club_member_tag_assignments;
create policy "club_member_tag_assignments_insert"
  on public.club_member_tag_assignments
  for insert
  to authenticated
  with check (
    exists (
      select 1
      from public.club_member_tags t
      where t.id = tag_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_tags')
        )
    )
  );

drop policy if exists "club_member_tag_assignments_update" on public.club_member_tag_assignments;
create policy "club_member_tag_assignments_update"
  on public.club_member_tag_assignments
  for update
  to authenticated
  using (
    exists (
      select 1
      from public.club_member_tags t
      where t.id = tag_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_tags')
        )
    )
  )
  with check (
    exists (
      select 1
      from public.club_member_tags t
      where t.id = tag_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_tags')
        )
    )
  );

drop policy if exists "club_member_tag_assignments_delete" on public.club_member_tag_assignments;
create policy "club_member_tag_assignments_delete"
  on public.club_member_tag_assignments
  for delete
  to authenticated
  using (
    exists (
      select 1
      from public.club_member_tags t
      where t.id = tag_id
        and (
          public.is_club_officer(t.club_id, auth.uid())
          or public.has_club_permission(t.club_id, auth.uid(), 'members.manage_tags')
        )
    )
  );

-- ─── 5. Update seed_default_club_roles (Officers can manage member tags) ───

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
    'members.view', 'members.invite', 'members.manage_tags',
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

-- ─── 6. Backfill: grant members.manage_tags to system President & Officer ───

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_tags'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_tags'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
