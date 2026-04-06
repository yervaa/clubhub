-- Club-specific committees (definitions + member assignments).
-- Apply after 028 (member tags). Idempotent where possible.

-- ─── 1. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.manage_committees', 'Create committees and assign members to them')
on conflict (key) do nothing;

-- ─── 2. Tables ───────────────────────────────────────────────────────────────

create table if not exists public.club_committees (
  id         uuid        primary key default gen_random_uuid(),
  club_id    uuid        not null references public.clubs(id) on delete cascade,
  name       text        not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint club_committees_name_nonempty check (char_length(trim(name)) >= 1)
);

comment on table public.club_committees is 'Named subgroups within a club (distinct from tags and RBAC roles).';

create unique index if not exists club_committees_club_name_norm_idx
  on public.club_committees (club_id, lower(trim(name)));

create index if not exists club_committees_club_id_idx
  on public.club_committees (club_id);

drop trigger if exists club_committees_updated_at on public.club_committees;
create trigger club_committees_updated_at
  before update on public.club_committees
  for each row execute function public.touch_updated_at();

create table if not exists public.club_committee_members (
  committee_id uuid        not null references public.club_committees(id) on delete cascade,
  user_id      uuid        not null references public.profiles(id) on delete cascade,
  joined_at    timestamptz not null default now(),
  added_by     uuid        null references public.profiles(id) on delete set null,
  primary key (committee_id, user_id)
);

comment on table public.club_committee_members is 'Membership in a club committee (a user may belong to many committees).';

create index if not exists club_committee_members_user_id_idx
  on public.club_committee_members (user_id);

-- ─── 3. Triggers ─────────────────────────────────────────────────────────────

create or replace function public.enforce_club_committee_member()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_club_id uuid;
begin
  select c.club_id into v_club_id
  from public.club_committees c
  where c.id = new.committee_id;

  if v_club_id is null then
    raise exception 'Committee not found';
  end if;

  if not exists (
    select 1
    from public.club_members cm
    where cm.club_id = v_club_id
      and cm.user_id = new.user_id
  ) then
    raise exception 'User must be a member of this club to join a committee';
  end if;

  return new;
end;
$$;

drop trigger if exists club_committee_members_enforce_member on public.club_committee_members;
create trigger club_committee_members_enforce_member
  before insert or update on public.club_committee_members
  for each row execute function public.enforce_club_committee_member();

create or replace function public.sync_club_committee_members_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_committee_members cm
  using public.club_committees c
  where cm.committee_id = c.id
    and c.club_id = old.club_id
    and cm.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_committee_members on public.club_members;
create trigger club_members_cleanup_committee_members
  after delete on public.club_members
  for each row execute function public.sync_club_committee_members_on_member_leave();

-- ─── 4. Row-Level Security ───────────────────────────────────────────────────

alter table public.club_committees enable row level security;
alter table public.club_committee_members enable row level security;

drop policy if exists "club_committees_select" on public.club_committees;
create policy "club_committees_select"
  on public.club_committees
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_committees.club_id
        and cm.user_id = auth.uid()
    )
  );

drop policy if exists "club_committees_insert" on public.club_committees;
create policy "club_committees_insert"
  on public.club_committees
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_committees')
  );

drop policy if exists "club_committees_update" on public.club_committees;
create policy "club_committees_update"
  on public.club_committees
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_committees')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_committees')
  );

drop policy if exists "club_committees_delete" on public.club_committees;
create policy "club_committees_delete"
  on public.club_committees
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_committees')
  );

drop policy if exists "club_committee_members_select" on public.club_committee_members;
create policy "club_committee_members_select"
  on public.club_committee_members
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.club_committees c
      join public.club_members cm on cm.club_id = c.club_id and cm.user_id = auth.uid()
      where c.id = club_committee_members.committee_id
    )
  );

drop policy if exists "club_committee_members_insert" on public.club_committee_members;
create policy "club_committee_members_insert"
  on public.club_committee_members
  for insert
  to authenticated
  with check (
    exists (
      select 1
      from public.club_committees c
      where c.id = committee_id
        and (
          public.is_club_officer(c.club_id, auth.uid())
          or public.has_club_permission(c.club_id, auth.uid(), 'members.manage_committees')
        )
    )
  );

drop policy if exists "club_committee_members_update" on public.club_committee_members;
create policy "club_committee_members_update"
  on public.club_committee_members
  for update
  to authenticated
  using (
    exists (
      select 1
      from public.club_committees c
      where c.id = committee_id
        and (
          public.is_club_officer(c.club_id, auth.uid())
          or public.has_club_permission(c.club_id, auth.uid(), 'members.manage_committees')
        )
    )
  )
  with check (
    exists (
      select 1
      from public.club_committees c
      where c.id = committee_id
        and (
          public.is_club_officer(c.club_id, auth.uid())
          or public.has_club_permission(c.club_id, auth.uid(), 'members.manage_committees')
        )
    )
  );

drop policy if exists "club_committee_members_delete" on public.club_committee_members;
create policy "club_committee_members_delete"
  on public.club_committee_members
  for delete
  to authenticated
  using (
    exists (
      select 1
      from public.club_committees c
      where c.id = committee_id
        and (
          public.is_club_officer(c.club_id, auth.uid())
          or public.has_club_permission(c.club_id, auth.uid(), 'members.manage_committees')
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
    'members.view', 'members.invite', 'members.manage_tags', 'members.manage_committees',
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

-- ─── 6. Backfill: grant members.manage_committees to President & Officer ─────

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_committees'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_committees'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
