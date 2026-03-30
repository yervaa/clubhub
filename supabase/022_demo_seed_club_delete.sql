-- ─── 022: Allow demo / admin teardown of clubs despite RBAC delete guards ─────
-- Problem: CASCADE delete from clubs removes club_roles and member_roles, which
-- hit prevent_deleting_system_roles and prevent_removing_last_president.
-- Solution: a transaction-local GUC set only from a SECURITY DEFINER RPC that
-- service_role may call (demo seed reset). Normal app paths stay protected.

create or replace function public.prevent_deleting_system_roles()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.is_system = true then
    if coalesce(current_setting('app.allow_club_cascade_delete', true), '') = 'on' then
      return old;
    end if;
    raise exception 'System roles (President, Officer, Member) cannot be deleted';
  end if;
  return old;
end;
$$;

create or replace function public.prevent_removing_last_president()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role_name            text;
  v_remaining_presidents integer;
begin
  if coalesce(current_setting('app.allow_club_cascade_delete', true), '') = 'on' then
    return old;
  end if;

  select cr.name into v_role_name
  from public.club_roles cr
  where cr.id = old.role_id;

  if v_role_name = 'President' then
    select count(*) into v_remaining_presidents
    from public.member_roles mr
    join public.club_roles   cr on cr.id = mr.role_id
    where mr.club_id   = old.club_id
      and cr.name      = 'President'
      and mr.user_id  <> old.user_id;

    if v_remaining_presidents = 0 then
      raise exception 'Cannot remove the last President from a club';
    end if;
  end if;

  return old;
end;
$$;

-- Deletes clubs by join_code with FK cascades; returns number of rows removed.
create or replace function public.delete_demo_clubs_by_join_codes(p_join_codes text[])
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted_count integer := 0;
begin
  if p_join_codes is null or cardinality(p_join_codes) = 0 then
    return 0;
  end if;

  perform set_config('app.allow_club_cascade_delete', 'on', true);

  delete from public.clubs c
  where c.join_code = any(
    select upper(trim(x))
    from unnest(p_join_codes) as t(x)
  );

  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;

comment on function public.delete_demo_clubs_by_join_codes(text[]) is
  'Demo seed / service-role only: delete clubs by join_code bypassing RBAC delete triggers.';

revoke all on function public.delete_demo_clubs_by_join_codes(text[]) from public;
grant execute on function public.delete_demo_clubs_by_join_codes(text[]) to service_role;
