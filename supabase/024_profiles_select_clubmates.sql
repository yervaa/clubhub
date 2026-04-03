-- ─── 024: Allow members to see clubmates' profile names ───────────────────────
-- Problem: profiles SELECT was only "own row", so nested selects like
--   club_members → profiles (tasks, RBAC role editor) and direct
--   .from("profiles").in("id", …) for audit feeds returned empty for others.
-- get_club_members_for_view (SECURITY DEFINER) still worked; other UI did not.
--
-- Solution: permissive policy — any authenticated user may read profiles for
-- users who share at least one club_members.club_id with them.

drop policy if exists "profiles_select_clubmates" on public.profiles;

create policy "profiles_select_clubmates"
on public.profiles
for select
to authenticated
using (
  exists (
    select 1
    from public.club_members cm_self
    inner join public.club_members cm_other
      on cm_other.club_id = cm_self.club_id
     and cm_other.user_id = profiles.id
    where cm_self.user_id = auth.uid()
  )
);

comment on policy "profiles_select_clubmates" on public.profiles is
  'Club members can read display fields for other members of clubs they belong to.';
