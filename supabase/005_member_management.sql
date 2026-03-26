-- ClubHub member management helpers
-- Apply this after earlier schema/auth migrations.

create or replace function public.get_club_members_for_view(target_club_id uuid)
returns table (
  user_id uuid,
  full_name text,
  email text,
  role text
)
language sql
stable
security definer
set search_path = public
as $$
  select
    cm.user_id,
    p.full_name,
    p.email,
    cm.role
  from public.club_members cm
  left join public.profiles p on p.id = cm.user_id
  where cm.club_id = target_club_id
    and public.is_club_member(target_club_id, auth.uid())
  order by
    case when cm.role = 'officer' then 0 else 1 end,
    nullif(trim(coalesce(p.full_name, '')), ''),
    coalesce(p.email, cm.user_id::text);
$$;

revoke all on function public.get_club_members_for_view(uuid) from public;
grant execute on function public.get_club_members_for_view(uuid) to authenticated;

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
    and cm.user_id = target_user_id;

  if existing_role is null then
    return 'not_found';
  end if;

  if existing_role = 'officer' and new_role = 'member' then
    select count(*)
    into officer_count
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.role = 'officer';

    if officer_count <= 1 then
      return 'last_officer';
    end if;
  end if;

  update public.club_members
  set role = new_role
  where club_id = target_club_id
    and user_id = target_user_id;

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
  officer_count integer;
begin
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
    and cm.user_id = target_user_id;

  if existing_role is null then
    return 'not_found';
  end if;

  if existing_role = 'officer' then
    select count(*)
    into officer_count
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.role = 'officer';

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
