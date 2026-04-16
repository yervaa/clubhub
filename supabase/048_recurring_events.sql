-- Recurring events: explicit series + concrete generated event rows.
-- Keep ClubHub behavior unchanged by storing each occurrence as a normal `events` row.

create table if not exists public.event_series (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs(id) on delete cascade,
  created_by uuid not null references public.profiles(id) on delete cascade,
  title text not null check (char_length(trim(title)) between 3 and 160),
  description text not null check (char_length(trim(description)) between 3 and 2000),
  location text not null check (char_length(trim(location)) between 2 and 160),
  event_type text not null check (char_length(trim(event_type)) between 2 and 50),
  capacity integer null check (capacity is null or (capacity >= 1 and capacity <= 5000)),
  starts_at timestamptz not null,
  duration_minutes integer not null check (duration_minutes between 1 and 1440),
  recurrence_type text not null check (recurrence_type in ('weekly', 'biweekly', 'monthly')),
  end_type text not null check (end_type in ('after_count', 'until_date')),
  occurrence_count integer null check (occurrence_count is null or occurrence_count between 1 and 52),
  until_date date null,
  created_at timestamptz not null default timezone('utc'::text, now()),
  updated_at timestamptz not null default timezone('utc'::text, now()),
  constraint event_series_end_condition_check check (
    (end_type = 'after_count' and occurrence_count is not null and until_date is null)
    or
    (end_type = 'until_date' and until_date is not null and occurrence_count is null)
  )
);

create index if not exists idx_event_series_club_id on public.event_series(club_id);
create index if not exists idx_event_series_created_by on public.event_series(created_by);

alter table public.events
  add column if not exists series_id uuid null references public.event_series(id) on delete cascade,
  add column if not exists series_occurrence integer null check (series_occurrence is null or series_occurrence >= 1);

create index if not exists idx_events_series_id on public.events(series_id);
create unique index if not exists idx_events_series_occurrence_uniq
  on public.events(series_id, series_occurrence)
  where series_id is not null;

alter table public.event_series enable row level security;

drop policy if exists "event_series_select_member" on public.event_series;
create policy "event_series_select_member"
on public.event_series
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

drop policy if exists "event_series_insert_rbac" on public.event_series;
create policy "event_series_insert_rbac"
on public.event_series
for insert
to authenticated
with check (
  auth.uid() = created_by
  and (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'events.create')
  )
);

drop policy if exists "event_series_update_rbac" on public.event_series;
create policy "event_series_update_rbac"
on public.event_series
for update
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'events.edit')
)
with check (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'events.edit')
);

drop policy if exists "event_series_delete_rbac" on public.event_series;
create policy "event_series_delete_rbac"
on public.event_series
for delete
to authenticated
using (
  public.is_club_officer(club_id, auth.uid())
  or public.has_club_permission(club_id, auth.uid(), 'events.delete')
);
