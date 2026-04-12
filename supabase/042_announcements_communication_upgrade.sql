-- ─── 042: Announcements communication (reads, polls, attachments, schedule) ─
-- Depends on: 001, 017, 019, 027 (membership_status), 012 (recent activity RPC)
-- Idempotent where possible.

-- ═══════════════════════════════════════════════════════════════════════════
-- 1. announcements: poll + scheduling
-- ═══════════════════════════════════════════════════════════════════════════

alter table public.announcements
  add column if not exists poll_question text,
  add column if not exists poll_options jsonb,
  add column if not exists scheduled_for timestamptz,
  add column if not exists is_published boolean not null default true;

comment on column public.announcements.poll_question is 'Optional poll prompt; null means no poll.';
comment on column public.announcements.poll_options is 'JSON array of option strings when poll_question is set.';
comment on column public.announcements.scheduled_for is 'When set in the future with is_published=false, row is hidden until published.';
comment on column public.announcements.is_published is 'False for scheduled drafts; cron sets true when scheduled_for passes.';

update public.announcements
set is_published = true
where is_published is distinct from true;

create index if not exists idx_announcements_publish_schedule
  on public.announcements (club_id, scheduled_for, is_published)
  where is_published = false;

-- ═══════════════════════════════════════════════════════════════════════════
-- 2. announcement_reads
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.announcement_reads (
  id uuid primary key default gen_random_uuid(),
  announcement_id uuid not null references public.announcements(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  read_at timestamptz not null default now(),
  unique (announcement_id, user_id)
);

create index if not exists idx_announcement_reads_announcement_id
  on public.announcement_reads (announcement_id);

alter table public.announcement_reads enable row level security;

drop policy if exists "announcement_reads_insert_self" on public.announcement_reads;
create policy "announcement_reads_insert_self"
  on public.announcement_reads
  for insert
  to authenticated
  with check (
    auth.uid() = user_id
    and exists (
      select 1
      from public.announcements a
      where a.id = announcement_id
        and public.is_club_member(a.club_id, auth.uid())
        and a.is_published = true
        and (a.scheduled_for is null or a.scheduled_for <= now())
    )
  );

drop policy if exists "announcement_reads_update_self" on public.announcement_reads;
create policy "announcement_reads_update_self"
  on public.announcement_reads
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Users only read their own receipt rows directly; aggregates use SECURITY DEFINER RPCs.
drop policy if exists "announcement_reads_select_own" on public.announcement_reads;
create policy "announcement_reads_select_own"
  on public.announcement_reads
  for select
  to authenticated
  using (auth.uid() = user_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- 3. poll_votes
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.poll_votes (
  id uuid primary key default gen_random_uuid(),
  announcement_id uuid not null references public.announcements(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  option_index int not null,
  created_at timestamptz not null default now(),
  unique (announcement_id, user_id)
);

create index if not exists idx_poll_votes_announcement_id
  on public.poll_votes (announcement_id);

alter table public.poll_votes enable row level security;

drop policy if exists "poll_votes_select_own" on public.poll_votes;
create policy "poll_votes_select_own"
  on public.poll_votes
  for select
  to authenticated
  using (auth.uid() = user_id);

drop policy if exists "poll_votes_insert_self" on public.poll_votes;
create policy "poll_votes_insert_self"
  on public.poll_votes
  for insert
  to authenticated
  with check (
    auth.uid() = user_id
    and exists (
      select 1
      from public.announcements a
      where a.id = announcement_id
        and public.is_club_member(a.club_id, auth.uid())
        and a.is_published = true
        and (a.scheduled_for is null or a.scheduled_for <= now())
        and a.poll_question is not null
        and a.poll_options is not null
        and jsonb_typeof(a.poll_options) = 'array'
    )
  );

drop policy if exists "poll_votes_update_self" on public.poll_votes;
create policy "poll_votes_update_self"
  on public.poll_votes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (
    auth.uid() = user_id
    and exists (
      select 1
      from public.announcements a
      where a.id = announcement_id
        and public.is_club_member(a.club_id, auth.uid())
        and a.is_published = true
        and (a.scheduled_for is null or a.scheduled_for <= now())
        and a.poll_question is not null
    )
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- 4. announcement_attachments + storage bucket
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.announcement_attachments (
  id uuid primary key default gen_random_uuid(),
  announcement_id uuid not null references public.announcements(id) on delete cascade,
  -- Storage object path within bucket announcement-attachments (used for signed URLs).
  file_url text not null,
  file_name text not null,
  file_type text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists idx_announcement_attachments_announcement_id
  on public.announcement_attachments (announcement_id);

alter table public.announcement_attachments enable row level security;

drop policy if exists "announcement_attachments_select_member" on public.announcement_attachments;
create policy "announcement_attachments_select_member"
  on public.announcement_attachments
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.announcements a
      where a.id = announcement_id
        and public.is_club_member(a.club_id, auth.uid())
        and (
          (a.is_published = true and (a.scheduled_for is null or a.scheduled_for <= now()))
          or public.is_club_officer(a.club_id, auth.uid())
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.edit')
        )
    )
  );

drop policy if exists "announcement_attachments_insert_leadership" on public.announcement_attachments;
create policy "announcement_attachments_insert_leadership"
  on public.announcement_attachments
  for insert
  to authenticated
  with check (
    exists (
      select 1
      from public.announcements a
      where a.id = announcement_id
        and public.is_club_member(a.club_id, auth.uid())
        and (
          public.is_club_officer(a.club_id, auth.uid())
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.create')
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.edit')
        )
    )
  );

drop policy if exists "announcement_attachments_delete_leadership" on public.announcement_attachments;
create policy "announcement_attachments_delete_leadership"
  on public.announcement_attachments
  for delete
  to authenticated
  using (
    exists (
      select 1
      from public.announcements a
      where a.id = announcement_id
        and (
          public.is_club_officer(a.club_id, auth.uid())
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.delete')
        )
    )
  );

insert into storage.buckets (id, name, public)
values ('announcement-attachments', 'announcement-attachments', false)
on conflict (id) do update set public = excluded.public;

-- Service role uploads/downloads bypass RLS; optional authenticated read via signed URLs from app.

-- ═══════════════════════════════════════════════════════════════════════════
-- 5. event_reminder_dispatches (idempotent reminders)
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.event_reminder_dispatches (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.events(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (event_id, user_id)
);

create index if not exists idx_event_reminder_dispatches_event_id
  on public.event_reminder_dispatches (event_id);

alter table public.event_reminder_dispatches enable row level security;
-- No policies: server-side service role only.

-- ═══════════════════════════════════════════════════════════════════════════
-- 6. announcements SELECT: hide unpublished scheduled posts from regular members
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "announcements_select_member" on public.announcements;
drop policy if exists "announcements_select_visible" on public.announcements;
create policy "announcements_select_visible"
  on public.announcements
  for select
  to authenticated
  using (
    public.is_club_member(club_id, auth.uid())
    and (
      (
        is_published = true
        and (scheduled_for is null or scheduled_for <= now())
      )
      or public.is_club_officer(club_id, auth.uid())
      or public.has_club_permission(club_id, auth.uid(), 'announcements.edit')
    )
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- 7. SECURITY DEFINER RPCs (aggregates + officer reader list)
-- ═══════════════════════════════════════════════════════════════════════════

create or replace function public.get_club_announcement_read_summaries(p_club_id uuid)
returns table (
  announcement_id uuid,
  read_count bigint,
  member_count bigint
)
language sql
stable
security definer
set search_path = public
as $$
  with allowed as (
    select public.is_club_member(p_club_id, auth.uid()) as ok
  ),
  member_total as (
    select count(*)::bigint as c
    from public.club_members cm
    where cm.club_id = p_club_id
      and cm.membership_status = 'active'
  ),
  visible as (
    select a.id
    from public.announcements a
    where a.club_id = p_club_id
      and (select ok from allowed)
      and (
        (a.is_published = true and (a.scheduled_for is null or a.scheduled_for <= now()))
        or public.is_club_officer(p_club_id, auth.uid())
        or public.has_club_permission(p_club_id, auth.uid(), 'announcements.edit')
      )
  ),
  read_agg as (
    select ar.announcement_id, count(*)::bigint as rc
    from public.announcement_reads ar
    where ar.announcement_id in (select id from visible)
    group by ar.announcement_id
  )
  select
    v.id as announcement_id,
    coalesce(r.rc, 0)::bigint as read_count,
    (select c from member_total) as member_count
  from visible v
  left join read_agg r on r.announcement_id = v.id;
$$;

revoke all on function public.get_club_announcement_read_summaries(uuid) from public;
grant execute on function public.get_club_announcement_read_summaries(uuid) to authenticated;

create or replace function public.list_announcement_readers(p_announcement_id uuid)
returns table (
  user_id uuid,
  full_name text,
  email text,
  read_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  with a as (
    select ann.id, ann.club_id
    from public.announcements ann
    where ann.id = p_announcement_id
  ),
  allowed as (
    select
      exists (select 1 from a)
      and public.is_club_member((select club_id from a), auth.uid())
      and (
        public.is_club_officer((select club_id from a), auth.uid())
        or public.has_club_permission((select club_id from a), auth.uid(), 'announcements.edit')
      ) as ok
  )
  select
    ar.user_id,
    coalesce(nullif(trim(p.full_name), ''), '')::text as full_name,
    p.email::text,
    ar.read_at
  from public.announcement_reads ar
  join public.profiles p on p.id = ar.user_id
  where (select ok from allowed)
    and ar.announcement_id = p_announcement_id
  order by ar.read_at desc;
$$;

revoke all on function public.list_announcement_readers(uuid) from public;
grant execute on function public.list_announcement_readers(uuid) to authenticated;

create or replace function public.get_club_announcement_poll_summaries(p_club_id uuid)
returns table (
  announcement_id uuid,
  option_index int,
  vote_count bigint
)
language sql
stable
security definer
set search_path = public
as $$
  with allowed as (
    select public.is_club_member(p_club_id, auth.uid()) as ok
  ),
  visible as (
    select a.id
    from public.announcements a
    where a.club_id = p_club_id
      and (select ok from allowed)
      and a.poll_question is not null
      and (
        (a.is_published = true and (a.scheduled_for is null or a.scheduled_for <= now()))
        or public.is_club_officer(p_club_id, auth.uid())
        or public.has_club_permission(p_club_id, auth.uid(), 'announcements.edit')
      )
  )
  select
    pv.announcement_id,
    pv.option_index,
    count(*)::bigint as vote_count
  from public.poll_votes pv
  where pv.announcement_id in (select id from visible)
  group by pv.announcement_id, pv.option_index;
$$;

revoke all on function public.get_club_announcement_poll_summaries(uuid) from public;
grant execute on function public.get_club_announcement_poll_summaries(uuid) to authenticated;

-- ═══════════════════════════════════════════════════════════════════════════
-- 8. Recent activity: skip unpublished / future-scheduled announcements
-- ═══════════════════════════════════════════════════════════════════════════

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
      and a.is_published = true
      and (a.scheduled_for is null or a.scheduled_for <= now())

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

    union all

    select
      'attendance-' || ea.event_id::text as id,
      'attendance_marked'::text as kind,
      'Attendance marked for ' || e.title ||
        ' (' || count(ea.user_id)::text || ' present)' as message,
      max(ea.marked_at) as created_at
    from public.event_attendance ea
    join public.events e on e.id = ea.event_id
    where e.club_id = target_club_id
    group by ea.event_id, e.title

  ) activity
  where (select allowed from viewer)
  order by created_at desc
  limit 12;
$$;

revoke all on function public.get_club_recent_activity(uuid) from public;
grant execute on function public.get_club_recent_activity(uuid) to authenticated;
