-- Club-scoped optional contact info (phone + preference). Not on global profiles.
-- Self-service edits only; leadership may view for coordination. Apply after 039.

insert into public.permissions (key, description) values
  ('members.view_member_contact', 'View members’ optional club contact details (phone / preference) in member profile')
on conflict (key) do nothing;

create table if not exists public.club_member_contact (
  club_id    uuid not null references public.clubs(id) on delete cascade,
  user_id    uuid not null references public.profiles(id) on delete cascade,
  phone_number text,
  preferred_contact_method text,
  updated_at timestamptz not null default now(),
  primary key (club_id, user_id),
  constraint club_member_contact_phone_len
    check (phone_number is null or char_length(phone_number) <= 40),
  constraint club_member_contact_method_chk
    check (
      preferred_contact_method is null
      or preferred_contact_method in ('email', 'phone', 'either')
    )
);

comment on table public.club_member_contact is
  'Optional per-club reachability: phone and preferred method. Auth email stays on profiles; not exported in roster CSV v1.';

create index if not exists club_member_contact_club_idx
  on public.club_member_contact (club_id);

-- ─── Enforce target is a club member; only self may write; active membership required to write ─

create or replace function public.enforce_club_member_contact_write()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  if not exists (
    select 1
    from public.club_members cm
    where cm.club_id = new.club_id
      and cm.user_id = new.user_id
  ) then
    raise exception 'Club contact can only be stored for club members';
  end if;

  if new.user_id is distinct from auth.uid() then
    raise exception 'Members may only edit their own club contact';
  end if;

  if not exists (
    select 1
    from public.club_members cm
    where cm.club_id = new.club_id
      and cm.user_id = new.user_id
      and cm.membership_status = 'active'
  ) then
    raise exception 'Active membership is required to update club contact';
  end if;

  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists club_member_contact_enforce_write on public.club_member_contact;
create trigger club_member_contact_enforce_write
  before insert or update on public.club_member_contact
  for each row execute function public.enforce_club_member_contact_write();

-- ─── Cleanup when membership row is removed ─

create or replace function public.sync_club_member_contact_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_member_contact c
  where c.club_id = old.club_id
    and c.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_member_contact on public.club_members;
create trigger club_members_cleanup_member_contact
  after delete on public.club_members
  for each row execute function public.sync_club_member_contact_on_member_leave();

-- ─── RLS ─────────────────────────────────────────────────────────────────────

alter table public.club_member_contact enable row level security;

-- Viewer must be in the club; then: own row, or leadership read.
drop policy if exists "club_member_contact_select" on public.club_member_contact;
create policy "club_member_contact_select"
  on public.club_member_contact
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.club_members cm
      where cm.club_id = club_member_contact.club_id
        and cm.user_id = auth.uid()
    )
    and (
      club_member_contact.user_id = auth.uid()
      or public.is_club_officer(club_member_contact.club_id, auth.uid())
      or public.has_club_permission(
        club_member_contact.club_id,
        auth.uid(),
        'members.view_member_contact'
      )
    )
  );

drop policy if exists "club_member_contact_insert" on public.club_member_contact;
create policy "club_member_contact_insert"
  on public.club_member_contact
  for insert
  to authenticated
  with check (user_id = auth.uid());

drop policy if exists "club_member_contact_update" on public.club_member_contact;
create policy "club_member_contact_update"
  on public.club_member_contact
  for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

drop policy if exists "club_member_contact_delete" on public.club_member_contact;
create policy "club_member_contact_delete"
  on public.club_member_contact
  for delete
  to authenticated
  using (user_id = auth.uid());

-- ─── seed_default_club_roles — officers can view member contact ─

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
    'members.view_member_contact',
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
join public.permissions p on p.key = 'members.view_member_contact'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.view_member_contact'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
