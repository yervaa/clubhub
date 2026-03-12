-- ClubHub MVP schema for Supabase/Postgres
-- Apply this file in Supabase SQL Editor or with Supabase CLI.

create extension if not exists "pgcrypto";

-- Profiles
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null unique,
  created_at timestamptz not null default now()
);

-- Clubs
create table if not exists public.clubs (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) >= 2),
  description text not null default '',
  join_code text not null unique check (char_length(join_code) >= 6),
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Club memberships
create table if not exists public.club_members (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role text not null check (role in ('member', 'officer')),
  joined_at timestamptz not null default now(),
  unique (club_id, user_id)
);

-- Announcements
create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs(id) on delete cascade,
  title text not null check (char_length(title) >= 2),
  content text not null,
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Events
create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs(id) on delete cascade,
  title text not null check (char_length(title) >= 2),
  description text not null,
  location text not null,
  event_date timestamptz not null,
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- RSVPs
create table if not exists public.rsvps (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.events(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  status text not null check (status in ('yes', 'no', 'maybe')),
  created_at timestamptz not null default now(),
  unique (event_id, user_id)
);

create index if not exists idx_club_members_user_id on public.club_members (user_id);
create index if not exists idx_announcements_club_id on public.announcements (club_id);
create index if not exists idx_events_club_id on public.events (club_id);
create index if not exists idx_events_event_date on public.events (event_date);
create index if not exists idx_rsvps_event_id on public.rsvps (event_id);

-- Automatically create profile rows for new auth users.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, email)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    coalesce(new.email, '')
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Policy helper functions
create or replace function public.is_club_member(target_club_id uuid, target_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.club_members cm
    where cm.club_id = target_club_id and cm.user_id = target_user_id
  );
$$;

create or replace function public.is_club_officer(target_club_id uuid, target_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.user_id = target_user_id
      and cm.role = 'officer'
  );
$$;

alter table public.profiles enable row level security;
alter table public.clubs enable row level security;
alter table public.club_members enable row level security;
alter table public.announcements enable row level security;
alter table public.events enable row level security;
alter table public.rsvps enable row level security;

-- Profiles: users can read/update/insert their own profile.
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
on public.profiles
for select
to authenticated
using (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
on public.profiles
for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own"
on public.profiles
for insert
to authenticated
with check (auth.uid() = id);

-- Clubs: members can view; authenticated users can create; officers can manage.
drop policy if exists "clubs_select_member" on public.clubs;
create policy "clubs_select_member"
on public.clubs
for select
to authenticated
using (public.is_club_member(id, auth.uid()));

drop policy if exists "clubs_insert_authenticated" on public.clubs;
create policy "clubs_insert_authenticated"
on public.clubs
for insert
to authenticated
with check (auth.uid() = created_by);

drop policy if exists "clubs_update_officer" on public.clubs;
create policy "clubs_update_officer"
on public.clubs
for update
to authenticated
using (public.is_club_officer(id, auth.uid()))
with check (public.is_club_officer(id, auth.uid()));

drop policy if exists "clubs_delete_officer" on public.clubs;
create policy "clubs_delete_officer"
on public.clubs
for delete
to authenticated
using (public.is_club_officer(id, auth.uid()));

-- Club members: members can view same club roster.
drop policy if exists "club_members_select_same_club" on public.club_members;
create policy "club_members_select_same_club"
on public.club_members
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

-- User can join as member, or create own officer membership on club creation.
drop policy if exists "club_members_insert_self" on public.club_members;
create policy "club_members_insert_self"
on public.club_members
for insert
to authenticated
with check (
  auth.uid() = user_id
  and (
    role = 'member'
    or (
      role = 'officer'
      and exists (
        select 1
        from public.clubs c
        where c.id = club_id and c.created_by = auth.uid()
      )
    )
  )
);

drop policy if exists "club_members_update_officer" on public.club_members;
create policy "club_members_update_officer"
on public.club_members
for update
to authenticated
using (public.is_club_officer(club_id, auth.uid()))
with check (public.is_club_officer(club_id, auth.uid()));

drop policy if exists "club_members_delete_officer_or_self" on public.club_members;
create policy "club_members_delete_officer_or_self"
on public.club_members
for delete
to authenticated
using (
  auth.uid() = user_id
  or public.is_club_officer(club_id, auth.uid())
);

-- Announcements: members can read, officers can write.
drop policy if exists "announcements_select_member" on public.announcements;
create policy "announcements_select_member"
on public.announcements
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

drop policy if exists "announcements_insert_officer" on public.announcements;
create policy "announcements_insert_officer"
on public.announcements
for insert
to authenticated
with check (
  auth.uid() = created_by and public.is_club_officer(club_id, auth.uid())
);

drop policy if exists "announcements_update_officer" on public.announcements;
create policy "announcements_update_officer"
on public.announcements
for update
to authenticated
using (public.is_club_officer(club_id, auth.uid()))
with check (public.is_club_officer(club_id, auth.uid()));

drop policy if exists "announcements_delete_officer" on public.announcements;
create policy "announcements_delete_officer"
on public.announcements
for delete
to authenticated
using (public.is_club_officer(club_id, auth.uid()));

-- Events: members can read, officers can write.
drop policy if exists "events_select_member" on public.events;
create policy "events_select_member"
on public.events
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

drop policy if exists "events_insert_officer" on public.events;
create policy "events_insert_officer"
on public.events
for insert
to authenticated
with check (
  auth.uid() = created_by and public.is_club_officer(club_id, auth.uid())
);

drop policy if exists "events_update_officer" on public.events;
create policy "events_update_officer"
on public.events
for update
to authenticated
using (public.is_club_officer(club_id, auth.uid()))
with check (public.is_club_officer(club_id, auth.uid()));

drop policy if exists "events_delete_officer" on public.events;
create policy "events_delete_officer"
on public.events
for delete
to authenticated
using (public.is_club_officer(club_id, auth.uid()));

-- RSVPs: club members can read event RSVPs; users can upsert their own RSVP.
drop policy if exists "rsvps_select_member" on public.rsvps;
create policy "rsvps_select_member"
on public.rsvps
for select
to authenticated
using (
  exists (
    select 1
    from public.events e
    where e.id = event_id and public.is_club_member(e.club_id, auth.uid())
  )
);

drop policy if exists "rsvps_insert_self" on public.rsvps;
create policy "rsvps_insert_self"
on public.rsvps
for insert
to authenticated
with check (
  auth.uid() = user_id
  and exists (
    select 1
    from public.events e
    where e.id = event_id and public.is_club_member(e.club_id, auth.uid())
  )
);

drop policy if exists "rsvps_update_self" on public.rsvps;
create policy "rsvps_update_self"
on public.rsvps
for update
to authenticated
using (auth.uid() = user_id)
with check (
  auth.uid() = user_id
  and exists (
    select 1
    from public.events e
    where e.id = event_id and public.is_club_member(e.club_id, auth.uid())
  )
);

drop policy if exists "rsvps_delete_self" on public.rsvps;
create policy "rsvps_delete_self"
on public.rsvps
for delete
to authenticated
using (auth.uid() = user_id);
