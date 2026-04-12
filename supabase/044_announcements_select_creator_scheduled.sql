-- Allow the author to SELECT their own announcement while it is still unpublished
-- or scheduled (not yet visible to general members). They already pass INSERT RLS
-- with announcements.create and auth.uid() = created_by; this closes the gap where
-- SELECT required officer role or announcements.edit for drafts/scheduled rows.

drop policy if exists "announcements_select_visible" on public.announcements;

create policy "announcements_select_visible"
  on public.announcements
  for select
  to authenticated
  using (
    public.is_club_member(club_id, auth.uid())
    and (
      (
        is_published = true
        and (scheduled_for is null or scheduled_for <= now())
      )
      or public.is_club_officer(club_id, auth.uid())
      or public.has_club_permission(club_id, auth.uid(), 'announcements.edit')
      or created_by = auth.uid()
    )
  );

comment on policy "announcements_select_visible" on public.announcements is
  'Members see published (or past-due scheduled) posts; officers and announcements.edit see drafts; authors see their own rows.';
