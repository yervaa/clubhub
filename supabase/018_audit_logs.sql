-- ─── 018: Club Audit Logs ────────────────────────────────────────────────────
-- Depends on:
--   013_rbac_schema.sql   (club_roles, has_club_permission function)
--   016_rbac_permission_matrix.sql  (audit_logs.view permission seeded)
-- Idempotent: safe to run multiple times.

-- ─── Table ─────────────────────────────────────────────────────────────────

create table if not exists public.club_audit_logs (
  id             uuid        primary key default gen_random_uuid(),
  club_id        uuid        not null references public.clubs(id)       on delete cascade,
  actor_id       uuid        not null references public.profiles(id)    on delete cascade,
  action         text        not null,
  target_user_id uuid        null        references public.profiles(id) on delete set null,
  target_role_id uuid        null        references public.club_roles(id) on delete set null,
  metadata       jsonb       not null default '{}'::jsonb,
  created_at     timestamptz not null default now()
);

comment on table  public.club_audit_logs                is 'Append-only log of governance and RBAC actions within a club.';
comment on column public.club_audit_logs.action         is 'Machine-readable action key, e.g. role.created, president.added.';
comment on column public.club_audit_logs.target_user_id is 'Affected member, if any. Set to NULL when the profile is deleted.';
comment on column public.club_audit_logs.target_role_id is 'Affected role, if any. Set to NULL when the role is deleted.';
comment on column public.club_audit_logs.metadata       is 'Supplementary structured data (e.g. role_name for deleted roles).';

-- ─── Indexes ───────────────────────────────────────────────────────────────

create index if not exists club_audit_logs_club_id_idx   on public.club_audit_logs (club_id);
create index if not exists club_audit_logs_created_at_idx on public.club_audit_logs (created_at desc);
create index if not exists club_audit_logs_action_idx    on public.club_audit_logs (action);

-- ─── Row-Level Security ────────────────────────────────────────────────────
-- INSERT/UPDATE/DELETE are intentionally blocked for all authenticated users.
-- All writes happen through the service-role admin client in server actions.
-- Only users with the audit_logs.view permission can read entries for their club.

alter table public.club_audit_logs enable row level security;

-- Drop and recreate so this migration stays idempotent.
drop policy if exists "audit_logs_select_rbac" on public.club_audit_logs;

create policy "audit_logs_select_rbac"
  on public.club_audit_logs
  for select
  to authenticated
  using (
    public.has_club_permission(auth.uid(), club_id, 'audit_logs.view')
  );

-- No INSERT / UPDATE / DELETE policies — only the service-role admin client
-- may write to this table (it bypasses RLS entirely).
