-- ClubHub authorization hardening
-- Apply this after 001_mvp_schema.sql on existing projects.

create or replace function public.handle_new_club()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.club_members (club_id, user_id, role)
  values (new.id, new.created_by, 'officer')
  on conflict (club_id, user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_club_created on public.clubs;
create trigger on_club_created
after insert on public.clubs
for each row execute procedure public.handle_new_club();

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
  limit 1;
$$;

revoke all on function public.find_club_by_join_code(text) from public;
grant execute on function public.find_club_by_join_code(text) to authenticated;

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

drop policy if exists "clubs_update_officer" on public.clubs;
drop policy if exists "clubs_delete_officer" on public.clubs;

drop policy if exists "club_members_update_officer" on public.club_members;
drop policy if exists "club_members_delete_officer_or_self" on public.club_members;

drop policy if exists "club_members_insert_self" on public.club_members;
create policy "club_members_insert_self"
on public.club_members
for insert
to authenticated
with check (
  auth.uid() = user_id
  and role = 'member'
);

drop policy if exists "announcements_update_officer" on public.announcements;
drop policy if exists "announcements_delete_officer" on public.announcements;

drop policy if exists "events_update_officer" on public.events;
drop policy if exists "events_delete_officer" on public.events;
