create table if not exists public.event_attendance (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.events(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  marked_by uuid not null references public.profiles(id) on delete cascade,
  marked_at timestamptz not null default now(),
  unique (event_id, user_id)
);

create index if not exists idx_event_attendance_event_id on public.event_attendance (event_id);

alter table public.event_attendance enable row level security;

drop policy if exists "event_attendance_select_member" on public.event_attendance;
create policy "event_attendance_select_member"
on public.event_attendance
for select
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id and public.is_club_member(e.club_id, auth.uid())
  )
);

drop policy if exists "event_attendance_insert_officer" on public.event_attendance;
create policy "event_attendance_insert_officer"
on public.event_attendance
for insert
to authenticated
with check (
  auth.uid() = marked_by
  and exists (
    select 1
    from public.events e
    join public.club_members cm on cm.club_id = e.club_id and cm.user_id = user_id
    where e.id = event_id
      and public.is_club_officer(e.club_id, auth.uid())
  )
);

drop policy if exists "event_attendance_delete_officer" on public.event_attendance;
create policy "event_attendance_delete_officer"
on public.event_attendance
for delete
to authenticated
using (
  exists (
    select 1
    from public.events e
    join public.club_members cm on cm.club_id = e.club_id and cm.user_id = user_id
    where e.id = event_id
      and public.is_club_officer(e.club_id, auth.uid())
  )
);
