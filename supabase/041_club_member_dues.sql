-- Club-scoped member dues / payment status (operational, not a ledger). Apply after 040.
-- Leadership-only visibility — regular members cannot read their own row via RLS.

insert into public.permissions (key, description) values
  ('members.manage_member_dues', 'View and edit per-member dues status within a club (leadership only)')
on conflict (key) do nothing;

create table if not exists public.club_member_dues (
  club_id    uuid not null references public.clubs(id) on delete cascade,
  user_id    uuid not null references public.profiles(id) on delete cascade,
  status     text not null,
  notes      text not null default '',
  updated_at timestamptz not null default now(),
  updated_by uuid null references public.profiles(id) on delete set null,
  primary key (club_id, user_id),
  constraint club_member_dues_status_check
    check (status in ('unpaid', 'paid', 'partial', 'exempt', 'waived')),
  constraint club_member_dues_notes_max
    check (char_length(notes) <= 500)
);

comment on table public.club_member_dues is
  'Leadership-only dues/payment status for roster follow-up. Not on global profile; not in roster CSV export.';

create index if not exists club_member_dues_club_idx
  on public.club_member_dues (club_id);

-- ─── Target must be a club member ────────────────────────────────────────────

create or replace function public.enforce_club_member_dues_member()
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
    raise exception 'Dues can only be recorded for club members';
  end if;

  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end;
$$;

drop trigger if exists club_member_dues_enforce_member on public.club_member_dues;
create trigger club_member_dues_enforce_member
  before insert or update on public.club_member_dues
  for each row execute function public.enforce_club_member_dues_member();

-- ─── Cleanup when membership row is removed ──────────────────────────────────

create or replace function public.sync_club_member_dues_on_member_leave()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.club_member_dues d
  where d.club_id = old.club_id
    and d.user_id = old.user_id;
  return old;
end;
$$;

drop trigger if exists club_members_cleanup_member_dues on public.club_members;
create trigger club_members_cleanup_member_dues
  after delete on public.club_members
  for each row execute function public.sync_club_member_dues_on_member_leave();

-- ─── RLS (leadership only — same pattern as officer notes) ────────────────────

alter table public.club_member_dues enable row level security;

drop policy if exists "club_member_dues_select" on public.club_member_dues;
create policy "club_member_dues_select"
  on public.club_member_dues
  for select
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

drop policy if exists "club_member_dues_insert" on public.club_member_dues;
create policy "club_member_dues_insert"
  on public.club_member_dues
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

drop policy if exists "club_member_dues_update" on public.club_member_dues;
create policy "club_member_dues_update"
  on public.club_member_dues
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

drop policy if exists "club_member_dues_delete" on public.club_member_dues;
create policy "club_member_dues_delete"
  on public.club_member_dues
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

-- ─── seed_default_club_roles ─────────────────────────────────────────────────

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
    'members.manage_member_dues',
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
join public.permissions p on p.key = 'members.manage_member_dues'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.manage_member_dues'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
