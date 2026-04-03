-- ─── 023: Pilot showcase reset (destructive) ────────────────────────────────
-- Clears notifications, audit logs, and all clubs (CASCADE removes dependent
-- rows: events, tasks, RBAC, members, etc.). Does not delete auth.users.
-- The pilot-showcase TypeScript script deletes auth users after calling this RPC.
--
-- Apply once per Supabase project, then run: npm run seed:pilot-showcase
-- Requires 022_demo_seed_club_delete.sql (or equivalent) so RBAC triggers honor
-- app.allow_club_cascade_delete during CASCADE deletes from public.clubs.

create or replace function public.pilot_showcase_reset()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Hosted Postgres may reject bare DELETE without WHERE; WHERE true keeps full-table clear.
  delete from public.notifications where true;
  delete from public.club_audit_logs where true;
  -- Same GUC as delete_demo_clubs_by_join_codes (022): bypass RBAC delete guards on CASCADE from clubs.
  perform set_config('app.allow_club_cascade_delete', 'on', true);
  delete from public.clubs where true;
end;
$$;

comment on function public.pilot_showcase_reset() is
  'Destructive: clears notifications, audit logs, and all clubs. For pilot re-seed only.';

revoke all on function public.pilot_showcase_reset() from public;
grant execute on function public.pilot_showcase_reset() to service_role;
