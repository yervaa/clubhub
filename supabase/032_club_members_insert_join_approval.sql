-- Enforce join approval at RLS: self-service member inserts only when the club
-- does not require approval (approve_club_join_request uses SECURITY DEFINER).
-- Apply after 031.

drop policy if exists "club_members_insert_self" on public.club_members;

create policy "club_members_insert_self"
  on public.club_members
  for insert
  to authenticated
  with check (
    auth.uid() = user_id
    and role = 'member'
    and exists (
      select 1
      from public.clubs c
      where c.id = club_id
        and coalesce(c.require_join_approval, false) = false
        and coalesce(c.status, 'active') <> 'archived'
    )
  );
