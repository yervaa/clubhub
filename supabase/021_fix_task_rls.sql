-- ─── 021: Fix RLS infinite recursion in club_task_assignees ──────────────────
-- Root cause: club_tasks_select policy subqueries club_task_assignees, and
-- club_task_assignees_select policy subqueries club_tasks — a mutual reference
-- that Postgres detects as infinite recursion.
--
-- Fix: replace the club_task_assignees_select policy with one that uses a
-- SECURITY DEFINER helper function. The helper queries club_tasks and
-- club_members without triggering RLS (security definer bypasses it), breaking
-- the cycle entirely.
--
-- Idempotent: safe to run multiple times.

-- ─── Helper: membership check that bypasses RLS ────────────────────────────

create or replace function public.is_task_club_member(
  p_task_id uuid,
  p_user_id uuid
)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select exists (
    select 1
    from public.club_tasks   ct
    join public.club_members cm on cm.club_id = ct.club_id
    where ct.id         = p_task_id
      and cm.user_id    = p_user_id
  );
$$;

comment on function public.is_task_club_member(uuid, uuid) is
  'Returns true if p_user_id is a member of the club that owns p_task_id. '
  'SECURITY DEFINER so it can query club_tasks without re-entering its own RLS policy.';

revoke all on function public.is_task_club_member(uuid, uuid) from public;
grant execute on function public.is_task_club_member(uuid, uuid) to authenticated;

-- ─── Replace the recursive policy ──────────────────────────────────────────

drop policy if exists "club_task_assignees_select" on public.club_task_assignees;

create policy "club_task_assignees_select"
  on public.club_task_assignees
  for select
  to authenticated
  using (
    -- Any member of the club owning this task can read assignee rows.
    -- The helper function bypasses RLS on club_tasks to avoid recursion.
    public.is_task_club_member(task_id, auth.uid())
  );
