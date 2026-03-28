-- ─── 019: In-App Notifications ───────────────────────────────────────────────
-- Depends on: 001_mvp_schema.sql (profiles, clubs tables)
-- Idempotent: safe to run multiple times.

-- ─── Table ─────────────────────────────────────────────────────────────────

create table if not exists public.notifications (
  id         uuid        primary key default gen_random_uuid(),
  user_id    uuid        not null references public.profiles(id) on delete cascade,
  club_id    uuid        null        references public.clubs(id)  on delete cascade,
  type       text        not null,
  title      text        not null,
  body       text        not null default '',
  href       text        null,
  metadata   jsonb       not null default '{}'::jsonb,
  is_read    boolean     not null default false,
  created_at timestamptz not null default now()
);

comment on table  public.notifications               is 'In-app notifications delivered to individual users.';
comment on column public.notifications.type          is 'Machine-readable type key, e.g. announcement.posted, role.assigned.';
comment on column public.notifications.href          is 'Optional deep-link the user is navigated to when they click the notification.';
comment on column public.notifications.is_read       is 'False until the user explicitly reads or dismisses the notification.';

-- ─── Indexes ───────────────────────────────────────────────────────────────

-- Primary read path: fetch all notifications for a user sorted by newest first.
create index if not exists notifications_user_id_created_at_idx
  on public.notifications (user_id, created_at desc);

-- Fast unread-count queries (partial index — only unread rows are indexed).
create index if not exists notifications_user_unread_idx
  on public.notifications (user_id, is_read)
  where is_read = false;

-- ─── Row-Level Security ────────────────────────────────────────────────────
-- Users may only read and update their own notifications.
-- All inserts happen through the service-role admin client (bypasses RLS).

alter table public.notifications enable row level security;

drop policy if exists "notifications_select_own" on public.notifications;
create policy "notifications_select_own"
  on public.notifications
  for select
  to authenticated
  using (auth.uid() = user_id);

drop policy if exists "notifications_update_own" on public.notifications;
create policy "notifications_update_own"
  on public.notifications
  for update
  to authenticated
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- No INSERT / DELETE policies for authenticated users.
-- Inserts are handled exclusively by the service-role admin client.
-- Old notifications may be pruned via a scheduled job in a future phase.
