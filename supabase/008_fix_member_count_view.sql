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
