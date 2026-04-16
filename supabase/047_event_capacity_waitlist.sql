-- Event capacity limits + waitlist support.
-- Adds optional event capacity and waitlist-aware RSVP automation.

alter table public.events
add column if not exists capacity integer;

alter table public.events
drop constraint if exists events_capacity_check;

alter table public.events
add constraint events_capacity_check
check (capacity is null or (capacity >= 1 and capacity <= 5000));

alter table public.rsvps
add column if not exists waitlisted_at timestamptz;

alter table public.rsvps
add column if not exists promoted_at timestamptz;

alter table public.rsvps
drop constraint if exists rsvps_status_check;

alter table public.rsvps
add constraint rsvps_status_check
check (status in ('yes', 'no', 'maybe', 'waitlist'));

create index if not exists idx_rsvps_event_waitlist_order
  on public.rsvps (event_id, status, waitlisted_at, created_at, user_id);

create or replace function public.promote_event_waitlist_internal(
  target_event_id uuid
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_capacity integer;
  v_confirmed integer;
  v_promoted integer := 0;
  v_candidate_user_id uuid;
begin
  select e.capacity
  into v_capacity
  from public.events e
  where e.id = target_event_id
  for update;

  if not found then
    return 0;
  end if;

  select count(*)::integer
  into v_confirmed
  from public.rsvps r
  where r.event_id = target_event_id
    and r.status = 'yes';

  loop
    exit when v_capacity is not null and v_confirmed >= v_capacity;

    select r.user_id
    into v_candidate_user_id
    from public.rsvps r
    where r.event_id = target_event_id
      and r.status = 'waitlist'
    order by coalesce(r.waitlisted_at, r.created_at), r.created_at, r.user_id
    limit 1
    for update skip locked;

    exit when v_candidate_user_id is null;

    update public.rsvps
    set status = 'yes',
        waitlisted_at = null,
        promoted_at = now()
    where event_id = target_event_id
      and user_id = v_candidate_user_id;

    v_promoted := v_promoted + 1;
    v_confirmed := v_confirmed + 1;
    v_candidate_user_id := null;
  end loop;

  return v_promoted;
end;
$$;

revoke all on function public.promote_event_waitlist_internal(uuid) from public;

create or replace function public.reconcile_event_waitlist(
  target_event_id uuid
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_club_id uuid;
begin
  if auth.uid() is null then
    raise exception 'not_authenticated';
  end if;

  select e.club_id
  into v_club_id
  from public.events e
  where e.id = target_event_id;

  if v_club_id is null then
    raise exception 'event_not_found';
  end if;

  if not (
    public.is_club_officer(v_club_id, auth.uid())
    or public.has_club_permission(v_club_id, auth.uid(), 'events.edit')
  ) then
    raise exception 'not_allowed';
  end if;

  return public.promote_event_waitlist_internal(target_event_id);
end;
$$;

revoke all on function public.reconcile_event_waitlist(uuid) from public;
grant execute on function public.reconcile_event_waitlist(uuid) to authenticated;

create or replace function public.set_event_rsvp_with_capacity(
  target_event_id uuid,
  target_status text
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid;
  v_club_id uuid;
  v_capacity integer;
  v_existing_status text;
  v_existing_waitlisted_at timestamptz;
  v_final_status text;
  v_confirmed_excluding_self integer;
begin
  v_user_id := auth.uid();
  if v_user_id is null then
    raise exception 'not_authenticated';
  end if;

  if target_status not in ('yes', 'no', 'maybe') then
    raise exception 'invalid_status';
  end if;

  select e.club_id, e.capacity
  into v_club_id, v_capacity
  from public.events e
  where e.id = target_event_id
  for update;

  if v_club_id is null then
    raise exception 'event_not_found';
  end if;

  if not public.is_club_member(v_club_id, v_user_id) then
    raise exception 'not_allowed';
  end if;

  select r.status, r.waitlisted_at
  into v_existing_status, v_existing_waitlisted_at
  from public.rsvps r
  where r.event_id = target_event_id
    and r.user_id = v_user_id
  for update;

  if target_status = 'yes' then
    select count(*)::integer
    into v_confirmed_excluding_self
    from public.rsvps r
    where r.event_id = target_event_id
      and r.status = 'yes'
      and r.user_id <> v_user_id;

    if v_capacity is null or v_confirmed_excluding_self < v_capacity then
      v_final_status := 'yes';
    else
      v_final_status := 'waitlist';
    end if;
  else
    v_final_status := target_status;
  end if;

  if v_existing_status is null then
    insert into public.rsvps (event_id, user_id, status, waitlisted_at, promoted_at)
    values (
      target_event_id,
      v_user_id,
      v_final_status,
      case when v_final_status = 'waitlist' then now() else null end,
      null
    );
  else
    update public.rsvps
    set status = v_final_status,
        waitlisted_at = case
          when v_final_status = 'waitlist' then coalesce(v_existing_waitlisted_at, now())
          else null
        end,
        promoted_at = case
          when v_final_status = 'yes' and v_existing_status = 'waitlist' then now()
          else promoted_at
        end
    where event_id = target_event_id
      and user_id = v_user_id;
  end if;

  if v_existing_status = 'yes' and v_final_status <> 'yes' then
    perform public.promote_event_waitlist_internal(target_event_id);
  end if;

  return v_final_status;
end;
$$;

revoke all on function public.set_event_rsvp_with_capacity(uuid, text) from public;
grant execute on function public.set_event_rsvp_with_capacity(uuid, text) to authenticated;
