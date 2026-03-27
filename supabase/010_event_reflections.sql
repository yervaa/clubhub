create table if not exists public.event_reflections (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null unique references public.events(id) on delete cascade,
  what_worked text not null,
  what_didnt text not null,
  notes text,
  created_by uuid not null references public.profiles(id) on delete cascade,
  updated_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_event_reflections_event_id on public.event_reflections (event_id);

alter table public.event_reflections enable row level security;

drop policy if exists "event_reflections_select_officer" on public.event_reflections;
create policy "event_reflections_select_officer"
on public.event_reflections
for select
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_officer(e.club_id, auth.uid())
  )
);

drop policy if exists "event_reflections_insert_officer" on public.event_reflections;
create policy "event_reflections_insert_officer"
on public.event_reflections
for insert
to authenticated
with check (
  auth.uid() = created_by
  and auth.uid() = updated_by
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_officer(e.club_id, auth.uid())
  )
);

drop policy if exists "event_reflections_update_officer" on public.event_reflections;
create policy "event_reflections_update_officer"
on public.event_reflections
for update
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_officer(e.club_id, auth.uid())
  )
)
with check (
  auth.uid() = updated_by
  and exists (
    select 1
    from public.events e
    where e.id = event_id
      and public.is_club_officer(e.club_id, auth.uid())
  )
);
