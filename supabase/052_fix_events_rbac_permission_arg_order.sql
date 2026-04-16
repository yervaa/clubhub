-- Correct `has_club_permission(target_club_id, target_user_id, permission_key)` argument order
-- on events INSERT/UPDATE/DELETE policies (was inverted in 017).

drop policy if exists "events_insert_rbac" on public.events;
create policy "events_insert_rbac"
on public.events
for insert
to authenticated
with check (
  auth.uid() = created_by
  and (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'events.create')
  )
);

drop policy if exists "events_update_rbac" on public.events;
create policy "events_update_rbac"
on public.events
for update
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'events.edit')
)
with check (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'events.edit')
);

drop policy if exists "events_delete_rbac" on public.events;
create policy "events_delete_rbac"
on public.events
for delete
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'events.delete')
);
