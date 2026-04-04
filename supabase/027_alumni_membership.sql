-- Alumni membership: club-specific status on club_members (not profiles).
-- Active members have operational privileges via RBAC; alumni keep the row for history/read access.

-- ─── 1. Column ───────────────────────────────────────────────────────────────

alter table public.club_members
  add column if not exists membership_status text not null default 'active';

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'club_members_membership_status_check'
  ) then
    alter table public.club_members
      add constraint club_members_membership_status_check
      check (membership_status in ('active', 'alumni'));
  end if;
end $$;

create index if not exists idx_club_members_club_membership_status
  on public.club_members (club_id, membership_status);

comment on column public.club_members.membership_status is
  'active: current member; alumni: historical association, no operational privileges.';

-- ─── 2. Active membership helper (RSVP, tasks, etc.) ─────────────────────────

create or replace function public.is_club_member_active(target_club_id uuid, target_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.user_id = target_user_id
      and cm.membership_status = 'active'
  );
$$;

revoke all on function public.is_club_member_active(uuid, uuid) from public;
grant execute on function public.is_club_member_active(uuid, uuid) to authenticated;

-- Legacy: any row (active or alumni) — used for read access where alumni should still see content.
-- Officers must be active (alumni are not treated as officers for legacy checks).

create or replace function public.is_club_officer(target_club_id uuid, target_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.user_id = target_user_id
      and cm.role = 'officer'
      and cm.membership_status = 'active'
  );
$$;

-- ─── 3. RBAC sync: do not re-assign Member RBAC when marking alumni ───────────

create or replace function public.sync_rbac_role_on_member_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old_name     text;
  v_new_name     text;
  v_old_role_id  uuid;
  v_new_role_id  uuid;
begin
  if new.membership_status = 'alumni' then
    return new;
  end if;

  if old.role = new.role then
    return new;
  end if;

  v_old_name := case when old.role = 'officer' then 'Officer' else 'Member' end;
  v_new_name := case when new.role = 'officer' then 'Officer' else 'Member' end;

  select id into v_old_role_id
  from public.club_roles
  where club_id = new.club_id and name = v_old_name and is_system = true;

  select id into v_new_role_id
  from public.club_roles
  where club_id = new.club_id and name = v_new_name and is_system = true;

  if v_old_role_id is not null then
    delete from public.member_roles
    where user_id = new.user_id
      and club_id = new.club_id
      and role_id = v_old_role_id;
  end if;

  if v_new_role_id is not null then
    insert into public.member_roles (user_id, club_id, role_id)
    values (new.user_id, new.club_id, v_new_role_id)
    on conflict do nothing;
  end if;

  return new;
end;
$$;

-- ─── 4. Roster RPC ────────────────────────────────────────────────────────────

create or replace function public.get_club_members_for_view(target_club_id uuid)
returns table (
  user_id uuid,
  full_name text,
  email text,
  role text,
  membership_status text
)
language sql
stable
security definer
set search_path = public
set row_security = off
as $$
  select
    cm.user_id,
    p.full_name,
    p.email,
    cm.role,
    cm.membership_status
  from public.club_members cm
  left join public.profiles p on p.id = cm.user_id
  where cm.club_id = target_club_id
    and public.is_club_member(target_club_id, auth.uid())
  order by
    case when cm.membership_status = 'alumni' then 1 else 0 end,
    case when cm.role = 'officer' then 0 else 1 end,
    nullif(trim(coalesce(p.full_name, '')), ''),
    coalesce(p.email, cm.user_id::text);
$$;

revoke all on function public.get_club_members_for_view(uuid) from public;
grant execute on function public.get_club_members_for_view(uuid) to authenticated;

-- ─── 5. Member role / remove RPCs (active-only targets & officer counts) ─────

create or replace function public.update_club_member_role(
  target_club_id uuid,
  target_user_id uuid,
  new_role text
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  existing_role text;
  officer_count integer;
begin
  if new_role not in ('member', 'officer') then
    return 'invalid_role';
  end if;

  if not public.is_club_officer(target_club_id, auth.uid()) then
    return 'not_allowed';
  end if;

  if auth.uid() = target_user_id then
    return 'cannot_edit_self';
  end if;

  select cm.role
  into existing_role
  from public.club_members cm
  where cm.club_id = target_club_id
    and cm.user_id = target_user_id
    and cm.membership_status = 'active';

  if existing_role is null then
    return 'not_found';
  end if;

  if existing_role = 'officer' and new_role = 'member' then
    select count(*)
    into officer_count
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.role = 'officer'
      and cm.membership_status = 'active';

    if officer_count <= 1 then
      return 'last_officer';
    end if;
  end if;

  update public.club_members
  set role = new_role
  where club_id = target_club_id
    and user_id = target_user_id
    and membership_status = 'active';

  return 'ok';
end;
$$;

revoke all on function public.update_club_member_role(uuid, uuid, text) from public;
grant execute on function public.update_club_member_role(uuid, uuid, text) to authenticated;

create or replace function public.remove_club_member(
  target_club_id uuid,
  target_user_id uuid
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  existing_role text;
  v_status text;
  officer_count integer;
begin
  if not public.is_club_officer(target_club_id, auth.uid()) then
    return 'not_allowed';
  end if;

  if auth.uid() = target_user_id then
    return 'cannot_edit_self';
  end if;

  select cm.role, cm.membership_status
  into existing_role, v_status
  from public.club_members cm
  where cm.club_id = target_club_id
    and cm.user_id = target_user_id;

  if existing_role is null or v_status is null then
    return 'not_found';
  end if;

  -- Drop alumni from the roster entirely (no last-officer rule; RBAC already cleared).
  if v_status = 'alumni' then
    delete from public.club_members
    where club_id = target_club_id
      and user_id = target_user_id;
    return 'ok';
  end if;

  if existing_role = 'officer' then
    select count(*)
    into officer_count
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.role = 'officer'
      and cm.membership_status = 'active';

    if officer_count <= 1 then
      return 'last_officer';
    end if;
  end if;

  delete from public.club_members
  where club_id = target_club_id
    and user_id = target_user_id;

  return 'ok';
end;
$$;

revoke all on function public.remove_club_member(uuid, uuid) from public;
grant execute on function public.remove_club_member(uuid, uuid) to authenticated;

-- ─── 6. Mark alumni (strip RBAC, set status) ───────────────────────────────────

create or replace function public.set_club_membership_alumni(
  p_club_id uuid,
  p_target_user_id uuid
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.club_members%rowtype;
  v_remaining_presidents integer;
begin
  if not public.has_club_permission(p_club_id, auth.uid(), 'members.remove') then
    return 'not_allowed';
  end if;

  if auth.uid() = p_target_user_id then
    return 'cannot_edit_self';
  end if;

  select * into v_row
  from public.club_members
  where club_id = p_club_id
    and user_id = p_target_user_id;

  if not found then
    return 'not_found';
  end if;

  if v_row.membership_status = 'alumni' then
    return 'already_alumni';
  end if;

  if public.is_club_president(p_club_id, p_target_user_id) then
    select count(*) into v_remaining_presidents
    from public.member_roles mr
    join public.club_roles cr on cr.id = mr.role_id
    where mr.club_id = p_club_id
      and cr.name = 'President'
      and cr.is_system = true
      and mr.user_id <> p_target_user_id;

    if v_remaining_presidents = 0 then
      return 'last_president';
    end if;
  end if;

  delete from public.member_roles mr
  using public.club_roles cr
  where mr.user_id = p_target_user_id
    and mr.club_id = p_club_id
    and mr.role_id = cr.id
    and not (cr.name = 'President' and cr.is_system = true);

  delete from public.member_roles mr
  using public.club_roles cr
  where mr.user_id = p_target_user_id
    and mr.club_id = p_club_id
    and mr.role_id = cr.id
    and cr.name = 'President'
    and cr.is_system = true;

  update public.club_members
  set membership_status = 'alumni',
      role = 'member'
  where club_id = p_club_id
    and user_id = p_target_user_id;

  return 'ok';
end;
$$;

revoke all on function public.set_club_membership_alumni(uuid, uuid) from public;
grant execute on function public.set_club_membership_alumni(uuid, uuid) to authenticated;

-- ─── 7. RSVPs: only active members can write their own RSVP ───────────────────

drop policy if exists "rsvps_insert_self" on public.rsvps;
create policy "rsvps_insert_self"
on public.rsvps
for insert
to authenticated
with check (
  auth.uid() = user_id
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_member_active(e.club_id, auth.uid())
  )
);

drop policy if exists "rsvps_update_self" on public.rsvps;
create policy "rsvps_update_self"
on public.rsvps
for update
to authenticated
using (auth.uid() = user_id)
with check (
  auth.uid() = user_id
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_member_active(e.club_id, auth.uid())
  )
);

drop policy if exists "rsvps_delete_self" on public.rsvps;
create policy "rsvps_delete_self"
on public.rsvps
for delete
to authenticated
using (
  auth.uid() = user_id
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_member_active(e.club_id, auth.uid())
  )
);

-- ─── 8. Event attendance INSERT: only mark active members present ────────────

drop policy if exists "event_attendance_insert_rbac" on public.event_attendance;
create policy "event_attendance_insert_rbac"
on public.event_attendance
for insert
to authenticated
with check (
  auth.uid() = marked_by
  and exists (
    select 1
    from public.events e
    join public.club_members cm on cm.club_id = e.club_id and cm.user_id = user_id
    where e.id = event_id
      and cm.membership_status = 'active'
      and (
        public.is_club_officer(e.club_id, auth.uid())
        or public.has_club_permission(e.club_id, auth.uid(), 'attendance.mark')
      )
  )
);

-- ─── 9. Tasks: membership gate requires active (021 helper) ────────────────────

create or replace function public.is_task_club_member(
  p_task_id uuid,
  p_user_id uuid
)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select exists (
    select 1
    from public.club_tasks   ct
    join public.club_members cm on cm.club_id = ct.club_id
    where ct.id = p_task_id
      and cm.user_id = p_user_id
      and cm.membership_status = 'active'
  );
$$;

drop policy if exists "club_tasks_select" on public.club_tasks;
create policy "club_tasks_select"
  on public.club_tasks
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_tasks.club_id
        and cm.user_id = auth.uid()
        and cm.membership_status = 'active'
    )
    and (
      public.has_club_permission(club_tasks.club_id, auth.uid(), 'tasks.view')
      or club_tasks.created_by = auth.uid()
      or exists (
        select 1 from public.club_task_assignees cta
        where cta.task_id = club_tasks.id
          and cta.user_id = auth.uid()
      )
    )
  );
