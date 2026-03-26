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
  name text not null check (char_length(name) >= 1),
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
  title text not null check (char_length(title) >= 1),
  content text not null,
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Events
create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs(id) on delete cascade,
  title text not null check (char_length(title) >= 1),
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

create table if not exists public.event_attendance (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.events(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  marked_by uuid not null references public.profiles(id) on delete cascade,
  marked_at timestamptz not null default now(),
  unique (event_id, user_id)
);

create index if not exists idx_club_members_user_id on public.club_members (user_id);
create index if not exists idx_announcements_club_id on public.announcements (club_id);
create index if not exists idx_events_club_id on public.events (club_id);
create index if not exists idx_events_event_date on public.events (event_date);
create index if not exists idx_rsvps_event_id on public.rsvps (event_id);
create index if not exists idx_event_attendance_event_id on public.event_attendance (event_id);

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

-- Automatically make the club creator an officer member of the club.
create or replace function public.handle_new_club()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.club_members (club_id, user_id, role)
  values (new.id, new.created_by, 'officer')
  on conflict (club_id, user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_club_created on public.clubs;
create trigger on_club_created
after insert on public.clubs
for each row execute procedure public.handle_new_club();

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

create or replace function public.find_club_by_join_code(target_join_code text)
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select c.id
  from public.clubs c
  where c.join_code = upper(trim(target_join_code))
  limit 1;
$$;

revoke all on function public.find_club_by_join_code(text) from public;
grant execute on function public.find_club_by_join_code(text) to authenticated;

create or replace function public.ensure_club_creator_membership(target_club_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  club_creator_id uuid;
begin
  select c.created_by
  into club_creator_id
  from public.clubs c
  where c.id = target_club_id;

  if club_creator_id is null then
    return false;
  end if;

  if club_creator_id <> auth.uid() then
    return false;
  end if;

  insert into public.club_members (club_id, user_id, role)
  values (target_club_id, club_creator_id, 'officer')
  on conflict (club_id, user_id) do nothing;

  return true;
end;
$$;

revoke all on function public.ensure_club_creator_membership(uuid) from public;
grant execute on function public.ensure_club_creator_membership(uuid) to authenticated;

create or replace function public.get_club_members_for_view(target_club_id uuid)
returns table (
  user_id uuid,
  full_name text,
  email text,
  role text
)
language sql
stable
security definer
set search_path = public
as $$
  select
    cm.user_id,
    p.full_name,
    p.email,
    cm.role
  from public.club_members cm
  join public.profiles p on p.id = cm.user_id
  where cm.club_id = target_club_id
    and public.is_club_member(target_club_id, auth.uid())
  order by
    case when cm.role = 'officer' then 0 else 1 end,
    nullif(trim(p.full_name), ''),
    p.email;
$$;

revoke all on function public.get_club_members_for_view(uuid) from public;
grant execute on function public.get_club_members_for_view(uuid) to authenticated;

create or replace function public.get_club_recent_activity(target_club_id uuid)
returns table (
  id text,
  kind text,
  message text,
  created_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  with viewer as (
    select public.is_club_member(target_club_id, auth.uid()) as allowed
  )
  select *
  from (
    select
      'member-' || cm.id::text as id,
      'member_joined'::text as kind,
      coalesce(nullif(trim(p.full_name), ''), p.email, 'A member') || ' joined the club' as message,
      cm.joined_at as created_at
    from public.club_members cm
    join public.profiles p on p.id = cm.user_id
    where cm.club_id = target_club_id

    union all

    select
      'announcement-' || a.id::text as id,
      'announcement_posted'::text as kind,
      'New announcement posted: ' || a.title as message,
      a.created_at
    from public.announcements a
    where a.club_id = target_club_id

    union all

    select
      'event-' || e.id::text as id,
      'event_created'::text as kind,
      e.title || ' was scheduled' as message,
      e.created_at
    from public.events e
    where e.club_id = target_club_id

    union all

    select
      'rsvp-' || r.id::text as id,
      'rsvp_updated'::text as kind,
      coalesce(nullif(trim(p.full_name), ''), p.email, 'A member') || ' RSVP''d ' || upper(r.status) || ' for ' || e.title as message,
      r.created_at
    from public.rsvps r
    join public.events e on e.id = r.event_id
    join public.profiles p on p.id = r.user_id
    where e.club_id = target_club_id
  ) activity
  where (select allowed from viewer)
  order by created_at desc
  limit 12;
$$;

revoke all on function public.get_club_recent_activity(uuid) from public;
grant execute on function public.get_club_recent_activity(uuid) to authenticated;

create or replace function public.update_club_member_role(
  target_club_id uuid,
  target_user_id uuid,
  new_role text
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  existing_role text;
  officer_count integer;
begin
  if new_role not in ('member', 'officer') then
    return 'invalid_role';
  end if;

  if not public.is_club_officer(target_club_id, auth.uid()) then
    return 'not_allowed';
  end if;

  if auth.uid() = target_user_id then
    return 'cannot_edit_self';
  end if;

  select cm.role
  into existing_role
  from public.club_members cm
  where cm.club_id = target_club_id
    and cm.user_id = target_user_id;

  if existing_role is null then
    return 'not_found';
  end if;

  if existing_role = 'officer' and new_role = 'member' then
    select count(*)
    into officer_count
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.role = 'officer';

    if officer_count <= 1 then
      return 'last_officer';
    end if;
  end if;

  update public.club_members
  set role = new_role
  where club_id = target_club_id
    and user_id = target_user_id;

  return 'ok';
end;
$$;

revoke all on function public.update_club_member_role(uuid, uuid, text) from public;
grant execute on function public.update_club_member_role(uuid, uuid, text) to authenticated;

create or replace function public.remove_club_member(
  target_club_id uuid,
  target_user_id uuid
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  existing_role text;
  officer_count integer;
begin
  if not public.is_club_officer(target_club_id, auth.uid()) then
    return 'not_allowed';
  end if;

  if auth.uid() = target_user_id then
    return 'cannot_edit_self';
  end if;

  select cm.role
  into existing_role
  from public.club_members cm
  where cm.club_id = target_club_id
    and cm.user_id = target_user_id;

  if existing_role is null then
    return 'not_found';
  end if;

  if existing_role = 'officer' then
    select count(*)
    into officer_count
    from public.club_members cm
    where cm.club_id = target_club_id
      and cm.role = 'officer';

    if officer_count <= 1 then
      return 'last_officer';
    end if;
  end if;

  delete from public.club_members
  where club_id = target_club_id
    and user_id = target_user_id;

  return 'ok';
end;
$$;

revoke all on function public.remove_club_member(uuid, uuid) from public;
grant execute on function public.remove_club_member(uuid, uuid) to authenticated;

alter table public.profiles enable row level security;
alter table public.clubs enable row level security;
alter table public.club_members enable row level security;
alter table public.announcements enable row level security;
alter table public.events enable row level security;
alter table public.rsvps enable row level security;
alter table public.event_attendance enable row level security;

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

-- Clubs: members can view; authenticated users can create.
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
drop policy if exists "clubs_delete_officer" on public.clubs;

-- Club members: members can view same club roster.
drop policy if exists "club_members_select_same_club" on public.club_members;
create policy "club_members_select_same_club"
on public.club_members
for select
to authenticated
using (public.is_club_member(club_id, auth.uid()));

-- User can join as member. Officer membership is created by the club trigger.
drop policy if exists "club_members_insert_self" on public.club_members;
create policy "club_members_insert_self"
on public.club_members
for insert
to authenticated
with check (
  auth.uid() = user_id
  and role = 'member'
);

drop policy if exists "club_members_update_officer" on public.club_members;
drop policy if exists "club_members_delete_officer_or_self" on public.club_members;

-- Announcements: members can read, officers can create.
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
drop policy if exists "announcements_delete_officer" on public.announcements;

-- Events: members can read, officers can create.
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
drop policy if exists "events_delete_officer" on public.events;

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

-- Event attendance: club members can read; officers can mark present members.
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
