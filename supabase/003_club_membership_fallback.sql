-- ClubHub create-club fallback hardening
-- Apply this after existing authorization migrations.

create or replace function public.ensure_club_creator_membership(target_club_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  club_creator_id uuid;
begin
  select c.created_by
  into club_creator_id
  from public.clubs c
  where c.id = target_club_id;

  if club_creator_id is null then
    return false;
  end if;

  if club_creator_id <> auth.uid() then
    return false;
  end if;

  insert into public.club_members (club_id, user_id, role)
  values (target_club_id, club_creator_id, 'officer')
  on conflict (club_id, user_id) do nothing;

  return true;
end;
$$;

revoke all on function public.ensure_club_creator_membership(uuid) from public;
grant execute on function public.ensure_club_creator_membership(uuid) to authenticated;
