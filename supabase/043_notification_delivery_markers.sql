-- ─── 043: Markers for notification delivery (cron retry without duplicates) ──
-- Depends on: 019 (notifications), 042 (announcements schedule, event_reminder_dispatches)

-- When member-facing broadcast rows were inserted in `notifications` for this announcement.
alter table public.announcements
  add column if not exists member_broadcast_sent_at timestamptz;

comment on column public.announcements.member_broadcast_sent_at is
  'Set after announcement_created / poll_created notifications are successfully inserted (immediate or scheduled publish). Null means eligible for retry while published.';

-- Historical published rows: assume broadcast already happened (avoid mass retries).
update public.announcements
set member_broadcast_sent_at = coalesce(scheduled_for, created_at)
where member_broadcast_sent_at is null
  and is_published = true;

-- When in-app event_reminder notification insert succeeded for this (event, user).
alter table public.event_reminder_dispatches
  add column if not exists notified_at timestamptz;

comment on column public.event_reminder_dispatches.notified_at is
  'Set after event_reminder notification row is successfully inserted. Null means eligible for retry.';

-- Historical dispatches: assume notification was sent (pre-043 behavior).
update public.event_reminder_dispatches
set notified_at = created_at
where notified_at is null;
