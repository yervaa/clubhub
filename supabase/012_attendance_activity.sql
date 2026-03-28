-- Extend the recent activity RPC to include attendance_marked events.
-- Groups per event so one activity item appears per event, not one per member.
-- Safe to apply: uses CREATE OR REPLACE on the existing function.

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

    union all

    -- One activity item per event (grouped), timestamped at the most recent mark
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
