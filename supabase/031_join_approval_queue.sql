-- Join approval queue: optional per-club review before membership.
-- Apply after 030. Idempotent where possible.

-- ─── 1. Club setting ─────────────────────────────────────────────────────────

alter table public.clubs
  add column if not exists require_join_approval boolean not null default false;

comment on column public.clubs.require_join_approval is
  'When true, join code adds a pending request instead of immediate club_members row.';

-- ─── 2. Permission ───────────────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('members.review_join_requests', 'Approve or deny pending membership requests')
on conflict (key) do nothing;

-- ─── 3. Requests table ───────────────────────────────────────────────────────

create table if not exists public.club_join_requests (
  id           uuid        primary key default gen_random_uuid(),
  club_id      uuid        not null references public.clubs(id) on delete cascade,
  user_id      uuid        not null references public.profiles(id) on delete cascade,
  status       text        not null check (status in ('pending', 'approved', 'denied')),
  requested_at timestamptz not null default now(),
  reviewed_at  timestamptz null,
  reviewed_by  uuid        null references public.profiles(id) on delete set null
);

comment on table public.club_join_requests is 'Pending and historical join attempts when require_join_approval is on.';

create unique index if not exists club_join_requests_one_pending_per_user
  on public.club_join_requests (club_id, user_id)
  where status = 'pending';

create index if not exists club_join_requests_club_pending_idx
  on public.club_join_requests (club_id)
  where status = 'pending';

create index if not exists club_join_requests_user_idx
  on public.club_join_requests (user_id);

-- ─── 4. RLS (reads for reviewers + own rows; writes via RPC only) ─────────────

alter table public.club_join_requests enable row level security;

drop policy if exists "club_join_requests_select" on public.club_join_requests;
create policy "club_join_requests_select"
  on public.club_join_requests
  for select
  to authenticated
  using (
    user_id = auth.uid()
    or (
      public.is_club_officer(club_id, auth.uid())
      or public.has_club_permission(club_id, auth.uid(), 'members.review_join_requests')
    )
  );

-- ─── 5. RPC: submit (caller must use when club requires approval) ────────────

create or replace function public.submit_club_join_request(p_join_code text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_club_id   uuid;
  v_requires  boolean;
  v_status    text;
begin
  if auth.uid() is null then
    return 'not_authenticated';
  end if;

  select c.id, coalesce(c.require_join_approval, false), c.status
  into v_club_id, v_requires, v_status
  from public.clubs c
  where c.join_code = upper(trim(p_join_code))
  limit 1;

  if v_club_id is null then
    return 'invalid_code';
  end if;

  if v_status = 'archived' then
    return 'archived';
  end if;

  if not v_requires then
    return 'approval_not_required';
  end if;

  if exists (
    select 1 from public.club_members cm
    where cm.club_id = v_club_id and cm.user_id = auth.uid()
  ) then
    return 'already_member';
  end if;

  if exists (
    select 1 from public.club_join_requests r
    where r.club_id = v_club_id and r.user_id = auth.uid() and r.status = 'pending'
  ) then
    return 'pending_exists';
  end if;

  insert into public.club_join_requests (club_id, user_id, status)
  values (v_club_id, auth.uid(), 'pending');

  return 'ok';
exception
  when unique_violation then
    return 'pending_exists';
end;
$$;

revoke all on function public.submit_club_join_request(text) from public;
grant execute on function public.submit_club_join_request(text) to authenticated;

-- ─── 6. RPC: approve ─────────────────────────────────────────────────────────

create or replace function public.approve_club_join_request(
  p_club_id   uuid,
  p_request_id uuid
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  r record;
begin
  if auth.uid() is null then
    return 'not_authenticated';
  end if;

  if not (
    public.is_club_officer(p_club_id, auth.uid())
    or public.has_club_permission(p_club_id, auth.uid(), 'members.review_join_requests')
  ) then
    return 'not_allowed';
  end if;

  select * into r
  from public.club_join_requests
  where id = p_request_id
    and club_id = p_club_id
  for update;

  if not found then
    return 'not_found';
  end if;

  if r.status <> 'pending' then
    return 'not_pending';
  end if;

  if exists (
    select 1 from public.club_members cm
    where cm.club_id = p_club_id and cm.user_id = r.user_id
  ) then
    update public.club_join_requests
    set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid()
    where id = p_request_id;
    return 'ok';
  end if;

  insert into public.club_members (club_id, user_id, role)
  values (p_club_id, r.user_id, 'member');

  update public.club_join_requests
  set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid()
  where id = p_request_id;

  return 'ok';
exception
  when unique_violation then
    update public.club_join_requests
    set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid()
    where id = p_request_id;
    return 'ok';
end;
$$;

revoke all on function public.approve_club_join_request(uuid, uuid) from public;
grant execute on function public.approve_club_join_request(uuid, uuid) to authenticated;

-- ─── 7. RPC: deny ────────────────────────────────────────────────────────────

create or replace function public.deny_club_join_request(
  p_club_id    uuid,
  p_request_id uuid
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  if auth.uid() is null then
    return 'not_authenticated';
  end if;

  if not (
    public.is_club_officer(p_club_id, auth.uid())
    or public.has_club_permission(p_club_id, auth.uid(), 'members.review_join_requests')
  ) then
    return 'not_allowed';
  end if;

  update public.club_join_requests
  set status = 'denied', reviewed_at = now(), reviewed_by = auth.uid()
  where id = p_request_id
    and club_id = p_club_id
    and status = 'pending';

  get diagnostics n = row_count;
  if n = 0 then
    return 'not_found';
  end if;

  return 'ok';
end;
$$;

revoke all on function public.deny_club_join_request(uuid, uuid) from public;
grant execute on function public.deny_club_join_request(uuid, uuid) to authenticated;

-- ─── 8. Update seed_default_club_roles ───────────────────────────────────────

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

-- ─── 9. Backfill: grant members.review_join_requests ─────────────────────────

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.review_join_requests'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'members.review_join_requests'
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;
