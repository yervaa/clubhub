-- Per-user notification preferences: in-app + email by category, quiet hours, weekly digest.
-- Service role reads/writes for notification delivery; users manage their own row via RLS.

create table if not exists public.notification_preferences (
  user_id uuid primary key references public.profiles(id) on delete cascade,

  in_app_announcements boolean not null default true,
  email_announcements boolean not null default true,
  in_app_events boolean not null default true,
  email_events boolean not null default true,
  in_app_reminders boolean not null default true,
  email_reminders boolean not null default false,
  in_app_role_membership boolean not null default true,
  email_role_membership boolean not null default true,
  in_app_activity boolean not null default true,
  email_activity boolean not null default false,

  quiet_hours_enabled boolean not null default false,
  quiet_hours_start text null,
  quiet_hours_end text null,
  timezone text not null default 'UTC',

  weekly_digest_enabled boolean not null default false,

  created_at timestamptz not null default timezone('utc'::text, now()),
  updated_at timestamptz not null default timezone('utc'::text, now()),

  constraint notification_preferences_quiet_hours_time_format check (
    (quiet_hours_start is null and quiet_hours_end is null)
    or (
      quiet_hours_start ~ '^([01]\d|2[0-3]):([0-5]\d)$'
      and quiet_hours_end ~ '^([01]\d|2[0-3]):([0-5]\d)$'
    )
  )
);

comment on table public.notification_preferences is
  'User controls for in-app vs email by category, quiet hours for email, and weekly digest opt-in.';

create index if not exists idx_notification_preferences_weekly_digest
  on public.notification_preferences (weekly_digest_enabled)
  where weekly_digest_enabled = true;

alter table public.notification_preferences enable row level security;

drop policy if exists "notification_preferences_select_own" on public.notification_preferences;
create policy "notification_preferences_select_own"
  on public.notification_preferences
  for select
  to authenticated
  using (auth.uid() = user_id);

drop policy if exists "notification_preferences_insert_own" on public.notification_preferences;
create policy "notification_preferences_insert_own"
  on public.notification_preferences
  for insert
  to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "notification_preferences_update_own" on public.notification_preferences;
create policy "notification_preferences_update_own"
  on public.notification_preferences
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
