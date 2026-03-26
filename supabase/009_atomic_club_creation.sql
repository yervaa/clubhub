create or replace function public.create_club_with_creator_membership(
  target_club_id uuid,
  target_name text,
  target_description text,
  target_join_code text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'not_authenticated';
  end if;

  insert into public.clubs (
    id,
    name,
    description,
    join_code,
    created_by
  )
  values (
    target_club_id,
    target_name,
    target_description,
    upper(trim(target_join_code)),
    auth.uid()
  );

  insert into public.club_members (club_id, user_id, role)
  values (target_club_id, auth.uid(), 'officer')
  on conflict (club_id, user_id) do update
  set role = 'officer';

  return target_club_id;
end;
$$;

revoke all on function public.create_club_with_creator_membership(uuid, text, text, text) from public;
grant execute on function public.create_club_with_creator_membership(uuid, text, text, text) to authenticated;
