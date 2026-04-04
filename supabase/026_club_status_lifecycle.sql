-- Club lifecycle: active vs archived, leave / archive / delete RPCs.
-- Apply after 022 (demo delete overrides prevent_removing_last_president).

-- ─── 1. Club status ──────────────────────────────────────────────────────────

alter table public.clubs
  add column if not exists status text not null default 'active';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'clubs_status_check'
  ) then
    alter table public.clubs
      add constraint clubs_status_check
      check (status in ('active', 'archived'));
  end if;
end $$;

create index if not exists idx_clubs_status on public.clubs (status);

comment on column public.clubs.status is 'active: normal operation; archived: historical, read-only, hidden from active listings.';

-- ─── 2. Permission: club.archive (President gets all new permissions via seed; backfill per-club President roles) ─

insert into public.permissions (key, description) values
  ('club.archive', 'Archive the club (inactive historical record)')
on conflict (key) do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p on p.key = 'club.archive'
where cr.name = 'President'
  and cr.is_system = true
on conflict do nothing;

-- ─── 3. Join code lookup: active clubs only ──────────────────────────────────

create or replace function public.find_club_by_join_code(target_join_code text)
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select c.id
  from public.clubs c
  where c.join_code = upper(trim(target_join_code))
    and c.status = 'active'
  limit 1;
$$;

-- ─── 4. Last President guard: allow removal when club is archived ────────────

create or replace function public.prevent_removing_last_president()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role_name            text;
  v_remaining_presidents integer;
  v_club_status          text;
begin
  if coalesce(current_setting('app.allow_club_cascade_delete', true), '') = 'on' then
    return old;
  end if;

  select cr.name into v_role_name
  from public.club_roles cr
  where cr.id = old.role_id;

  if v_role_name = 'President' then
    select c.status into v_club_status
    from public.clubs c
    where c.id = old.club_id;

    if coalesce(v_club_status, 'active') = 'archived' then
      return old;
    end if;

    select count(*) into v_remaining_presidents
    from public.member_roles mr
    join public.club_roles cr on cr.id = mr.role_id
    where mr.club_id = old.club_id
      and cr.name = 'President'
      and cr.is_system = true
      and mr.user_id <> old.user_id;

    if v_remaining_presidents = 0 then
      raise exception 'Cannot remove the last President from a club';
    end if;
  end if;

  return old;
end;
$$;

-- ─── 5. leave_club_self — member removes own row (RLS has no self-delete policy) ─

create or replace function public.leave_club_self(p_club_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_status text;
  v_presidents integer;
begin
  if auth.uid() is null then
    return 'not_authenticated';
  end if;

  if not exists (
    select 1 from public.club_members cm
    where cm.club_id = p_club_id and cm.user_id = auth.uid()
  ) then
    return 'not_member';
  end if;

  select c.status into v_status from public.clubs c where c.id = p_club_id;
  if v_status is null then
    return 'not_found';
  end if;

  if coalesce(v_status, 'active') = 'active'
     and public.is_club_president(p_club_id, auth.uid()) then
    select count(*) into v_presidents
    from public.member_roles mr
    join public.club_roles cr on cr.id = mr.role_id
    where mr.club_id = p_club_id
      and cr.name = 'President'
      and cr.is_system = true;

    if v_presidents <= 1 then
      return 'last_president_active';
    end if;
  end if;

  delete from public.club_members
  where club_id = p_club_id and user_id = auth.uid();

  return 'ok';
end;
$$;

revoke all on function public.leave_club_self(uuid) from public;
grant execute on function public.leave_club_self(uuid) to authenticated;

comment on function public.leave_club_self(uuid) is
  'Authenticated member removes themselves from a club; blocks last President of an active club.';

-- ─── 6. archive_club ─────────────────────────────────────────────────────────

create or replace function public.archive_club(p_club_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_updated integer;
begin
  if auth.uid() is null then
    return 'not_authenticated';
  end if;

  if not public.has_club_permission(p_club_id, auth.uid(), 'club.archive') then
    return 'permission_denied';
  end if;

  update public.clubs
  set status = 'archived'
  where id = p_club_id
    and status = 'active';

  get diagnostics v_updated = row_count;
  if v_updated = 0 then
    return 'not_active';
  end if;

  return 'ok';
end;
$$;

revoke all on function public.archive_club(uuid) from public;
grant execute on function public.archive_club(uuid) to authenticated;

comment on function public.archive_club(uuid) is
  'President-only: mark club archived (inactive / read-only).';

-- ─── 7. delete_club_cascade — destructive teardown (demo pattern) ───────────

create or replace function public.delete_club_cascade(p_club_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    return 'not_authenticated';
  end if;

  if not public.has_club_permission(p_club_id, auth.uid(), 'club.delete') then
    return 'permission_denied';
  end if;

  perform set_config('app.allow_club_cascade_delete', 'on', true);

  delete from public.clubs where id = p_club_id;

  return 'ok';
end;
$$;

revoke all on function public.delete_club_cascade(uuid) from public;
grant execute on function public.delete_club_cascade(uuid) to authenticated;

comment on function public.delete_club_cascade(uuid) is
  'President-only: permanently delete club and all dependent rows (FK cascades).';
