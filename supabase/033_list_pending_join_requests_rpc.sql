-- Officers/reviewers must see requester names; profiles RLS only exposes clubmates (024).
-- SECURITY DEFINER RPC lists pending rows with names for authorized callers only.
-- Apply after 031.

create or replace function public.list_pending_club_join_requests(p_club_id uuid)
returns table (
  id uuid,
  user_id uuid,
  full_name text,
  requested_at timestamptz
)
language sql
security definer
set search_path = public
stable
as $$
  select
    r.id,
    r.user_id,
    coalesce(nullif(trim(coalesce(p.full_name, '')), ''), '(No name)')::text,
    r.requested_at
  from public.club_join_requests r
  left join public.profiles p on p.id = r.user_id
  where r.club_id = p_club_id
    and r.status = 'pending'
    and auth.uid() is not null
    and (
      public.is_club_officer(p_club_id, auth.uid())
      or public.has_club_permission(p_club_id, auth.uid(), 'members.review_join_requests')
    )
  order by r.requested_at asc;
$$;

revoke all on function public.list_pending_club_join_requests(uuid) from public;
grant execute on function public.list_pending_club_join_requests(uuid) to authenticated;
