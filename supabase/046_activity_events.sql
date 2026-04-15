-- ─── 046: Activity Events Feed ───────────────────────────────────────────────
-- Unified activity stream for dashboard + club overview.

create table if not exists public.activity_events (
  id           uuid primary key default gen_random_uuid(),
  type         text not null,
  actor_id     uuid not null references public.profiles(id) on delete cascade,
  club_id      uuid not null references public.clubs(id) on delete cascade,
  entity_id    uuid null,
  target_label text not null,
  href         text null,
  metadata     jsonb not null default '{}'::jsonb,
  created_at   timestamptz not null default now()
);

comment on table public.activity_events is 'Recent engagement events used for app activity feeds.';
comment on column public.activity_events.type is 'Machine-readable key: announcement.created, event.created, rsvp.submitted, attendance.marked, role.assigned, role.removed.';

create index if not exists activity_events_club_created_idx
  on public.activity_events (club_id, created_at desc);

create index if not exists activity_events_created_idx
  on public.activity_events (created_at desc);

alter table public.activity_events enable row level security;

drop policy if exists "activity_events_select_club_members" on public.activity_events;
create policy "activity_events_select_club_members"
  on public.activity_events
  for select
  to authenticated
  using (public.is_club_member(club_id, auth.uid()));

-- All writes happen through service role only.

alter table public.notifications
  add column if not exists activity_event_id uuid null references public.activity_events(id) on delete set null;
