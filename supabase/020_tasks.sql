-- ─── 020: Club Task Management System ────────────────────────────────────────
-- Depends on: 001_mvp_schema.sql, 013_rbac_foundation.sql,
--             016_rbac_permission_matrix.sql
-- Idempotent: safe to run multiple times.

-- ─── Tables ────────────────────────────────────────────────────────────────

create table if not exists public.club_tasks (
  id           uuid        primary key default gen_random_uuid(),
  club_id      uuid        not null references public.clubs(id)    on delete cascade,
  title        text        not null,
  description  text        null,
  status       text        not null default 'todo'
                           check (status in ('todo', 'in_progress', 'blocked', 'completed')),
  priority     text        not null default 'medium'
                           check (priority in ('low', 'medium', 'high', 'urgent')),
  due_at       timestamptz null,
  created_by   uuid        not null references public.profiles(id) on delete restrict,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  completed_at timestamptz null
);

comment on table  public.club_tasks             is 'Tasks and responsibilities assigned within a club.';
comment on column public.club_tasks.status      is 'todo | in_progress | blocked | completed';
comment on column public.club_tasks.priority    is 'low | medium | high | urgent';
comment on column public.club_tasks.completed_at is 'Set when status transitions to completed.';

create table if not exists public.club_task_assignees (
  task_id     uuid        not null references public.club_tasks(id)  on delete cascade,
  user_id     uuid        not null references public.profiles(id)    on delete cascade,
  assigned_at timestamptz not null default now(),
  primary key (task_id, user_id)
);

comment on table public.club_task_assignees is 'Members assigned to a task.';

-- ─── Trigger: auto-update updated_at ──────────────────────────────────────

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists club_tasks_updated_at on public.club_tasks;
create trigger club_tasks_updated_at
  before update on public.club_tasks
  for each row execute function public.touch_updated_at();

-- ─── Indexes ───────────────────────────────────────────────────────────────

create index if not exists club_tasks_club_id_created_at_idx
  on public.club_tasks (club_id, created_at desc);

create index if not exists club_tasks_club_id_status_idx
  on public.club_tasks (club_id, status);

create index if not exists club_tasks_due_at_idx
  on public.club_tasks (due_at)
  where due_at is not null;

create index if not exists club_task_assignees_user_id_idx
  on public.club_task_assignees (user_id);

create index if not exists club_task_assignees_task_id_idx
  on public.club_task_assignees (task_id);

-- ─── Row-Level Security ────────────────────────────────────────────────────
-- All writes (INSERT / UPDATE / DELETE) are performed through the service-role
-- admin client in server actions, matching the pattern from audit_logs.
-- RLS only gates SELECT access to protect data visibility.

alter table public.club_tasks          enable row level security;
alter table public.club_task_assignees enable row level security;

-- club_tasks SELECT:
-- A club member can read a task if they:
--   (a) hold the tasks.view permission (officers/presidents see everything), OR
--   (b) created the task themselves, OR
--   (c) are directly assigned to it.

drop policy if exists "club_tasks_select" on public.club_tasks;
create policy "club_tasks_select"
  on public.club_tasks
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_members cm
      where cm.club_id = club_tasks.club_id
        and cm.user_id = auth.uid()
    )
    and (
      public.has_club_permission(club_tasks.club_id, auth.uid(), 'tasks.view')
      or club_tasks.created_by = auth.uid()
      or exists (
        select 1 from public.club_task_assignees cta
        where cta.task_id = club_tasks.id
          and cta.user_id = auth.uid()
      )
    )
  );

-- club_task_assignees SELECT:
-- Mirrors the task-level visibility rule so nested selects return consistent data.

drop policy if exists "club_task_assignees_select" on public.club_task_assignees;
create policy "club_task_assignees_select"
  on public.club_task_assignees
  for select
  to authenticated
  using (
    exists (
      select 1 from public.club_tasks ct
      join public.club_members cm on cm.club_id = ct.club_id
      where ct.id = club_task_assignees.task_id
        and cm.user_id = auth.uid()
        and (
          public.has_club_permission(ct.club_id, auth.uid(), 'tasks.view')
          or ct.created_by = auth.uid()
          or club_task_assignees.user_id = auth.uid()
        )
    )
  );

-- ─── New Task Permissions ─────────────────────────────────────────────────

insert into public.permissions (key, description) values
  ('tasks.view',     'View all tasks in the club'),
  ('tasks.create',   'Create new club tasks'),
  ('tasks.edit',     'Edit any task title, description, or details'),
  ('tasks.delete',   'Delete club tasks'),
  ('tasks.assign',   'Assign or unassign members on tasks'),
  ('tasks.complete', 'Mark tasks as complete')
on conflict (key) do nothing;

-- ─── Update seed_default_club_roles (includes task permissions) ───────────

create or replace function public.seed_default_club_roles(
  p_club_id    uuid,
  p_creator_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_president_id uuid;
  v_officer_id   uuid;
  v_member_id    uuid;
begin
  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'President', 'Full control over the club', true)
  returning id into v_president_id;

  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Officer', 'Manages events, announcements, and members', true)
  returning id into v_officer_id;

  insert into public.club_roles (club_id, name, description, is_system)
  values (p_club_id, 'Member', 'Standard club member', true)
  returning id into v_member_id;

  -- President: all permissions.
  insert into public.role_permissions (role_id, permission_id)
  select v_president_id, p.id from public.permissions p;

  -- Officer: full day-to-day management including tasks.
  insert into public.role_permissions (role_id, permission_id)
  select v_officer_id, p.id
  from public.permissions p
  where p.key in (
    'members.view', 'members.invite',
    'announcements.create', 'announcements.edit', 'announcements.delete',
    'events.create', 'events.edit', 'events.delete',
    'attendance.mark', 'attendance.edit',
    'reflections.create', 'reflections.edit',
    'insights.view',
    'tasks.view', 'tasks.create', 'tasks.edit', 'tasks.assign', 'tasks.complete'
  );

  -- Member: read-only participation + own task completion.
  insert into public.role_permissions (role_id, permission_id)
  select v_member_id, p.id
  from public.permissions p
  where p.key in (
    'members.view',
    'insights.view',
    'tasks.view',
    'tasks.complete'
  );

  insert into public.member_roles (user_id, club_id, role_id)
  values (p_creator_id, p_club_id, v_president_id);
end;
$$;

revoke all on function public.seed_default_club_roles(uuid, uuid) from public;

-- ─── Re-seed task permissions for existing system roles ──────────────────

-- President: all task permissions.
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
cross join public.permissions p
where cr.name = 'President'
  and cr.is_system = true
  and p.key in ('tasks.view', 'tasks.create', 'tasks.edit', 'tasks.delete', 'tasks.assign', 'tasks.complete')
on conflict do nothing;

-- Officer: all task permissions except delete.
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p
  on p.key in ('tasks.view', 'tasks.create', 'tasks.edit', 'tasks.assign', 'tasks.complete')
where cr.name = 'Officer'
  and cr.is_system = true
on conflict do nothing;

-- Member: view and complete own tasks.
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
join public.permissions p
  on p.key in ('tasks.view', 'tasks.complete')
where cr.name = 'Member'
  and cr.is_system = true
on conflict do nothing;
