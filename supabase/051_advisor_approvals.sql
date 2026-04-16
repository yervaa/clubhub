-- Advisor approval workflow: per-club flags, event/announcement approval_status, new permissions, RLS updates.

-- ═══════════════════════════════════════════════════════════════════════════
-- 1. Club-level settings
-- ═══════════════════════════════════════════════════════════════════════════

alter table public.clubs
  add column if not exists require_event_approval boolean not null default false,
  add column if not exists require_announcement_approval boolean not null default false;

comment on column public.clubs.require_event_approval is
  'When true, new/changed events need advisor approval before members see them.';
comment on column public.clubs.require_announcement_approval is
  'When true, publishing intent goes to pending advisor review before members see content.';

-- ═══════════════════════════════════════════════════════════════════════════
-- 2. Events: approval columns
-- ═══════════════════════════════════════════════════════════════════════════

alter table public.events
  add column if not exists approval_status text not null default 'approved'
    check (approval_status in ('approved', 'pending', 'rejected')),
  add column if not exists approved_at timestamptz null,
  add column if not exists approved_by uuid null references public.profiles(id) on delete set null,
  add column if not exists rejection_reason text null;

comment on column public.events.approval_status is 'approved = member-visible (subject to RLS); pending/rejected = organizer/advisor only until approved.';
comment on column public.events.rejection_reason is 'Short advisor note when rejected; visible to organizers.';

create index if not exists idx_events_club_approval
  on public.events (club_id, approval_status)
  where approval_status <> 'approved';

-- ═══════════════════════════════════════════════════════════════════════════
-- 3. Announcements: approval columns (draft/pending distinct from is_published scheduling)
-- ═══════════════════════════════════════════════════════════════════════════

alter table public.announcements
  add column if not exists approval_status text not null default 'approved'
    check (approval_status in ('draft', 'pending', 'approved', 'rejected')),
  add column if not exists approved_at timestamptz null,
  add column if not exists approved_by uuid null references public.profiles(id) on delete set null,
  add column if not exists rejection_reason text null;

comment on column public.announcements.approval_status is
  'draft=WIP; pending=awaiting advisor; approved=may be published or scheduled; rejected=hidden from members.';

create index if not exists idx_announcements_club_approval
  on public.announcements (club_id, approval_status)
  where approval_status in ('pending', 'rejected');

-- Announcements: default added column is 'approved' for all rows — normalize:
update public.announcements
set approval_status = 'draft'
where is_published = false
  and (scheduled_for is null or scheduled_for <= now());

update public.announcements
set approval_status = 'approved'
where is_published = true
   or (is_published = false and scheduled_for is not null and scheduled_for > now());

-- ═══════════════════════════════════════════════════════════════════════════
-- 4. New permissions
-- ═══════════════════════════════════════════════════════════════════════════

insert into public.permissions (key, description)
values
  ('events.approve', 'Approve or reject club events before they are visible to members'),
  ('announcements.approve', 'Approve or reject announcements before members can see them')
on conflict (key) do nothing;

-- President: all permissions (including new keys)
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
cross join public.permissions p
where cr.name = 'President'
  and cr.is_system = true
  and not exists (
    select 1 from public.role_permissions rp2
    where rp2.role_id = cr.id and rp2.permission_id = p.id
  );

-- Advisor-named custom roles: grant approve permissions
insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
cross join public.permissions p
where cr.name = 'Advisor'
  and cr.is_system = false
  and p.key in ('events.approve', 'announcements.approve')
  and not exists (
    select 1 from public.role_permissions rp
    where rp.role_id = cr.id and rp.permission_id = p.id
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- 5. RPC: list user ids with a permission in a club (for notifications; service use)
-- ═══════════════════════════════════════════════════════════════════════════

create or replace function public.list_club_members_with_permission(
  p_club_id uuid,
  p_permission_key text
)
returns table (user_id uuid)
language sql
stable
security definer
set search_path = public
as $$
  select distinct mr.user_id
  from public.member_roles mr
  join public.role_permissions rp on rp.role_id = mr.role_id
  join public.permissions p on p.id = rp.permission_id
  where mr.club_id = p_club_id
    and p.key = p_permission_key;
$$;

revoke all on function public.list_club_members_with_permission(uuid, text) from public;
grant execute on function public.list_club_members_with_permission(uuid, text) to service_role;

-- ═══════════════════════════════════════════════════════════════════════════
-- 6. events SELECT: members only see approved; creators + editors + approvers see more
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "events_select_member" on public.events;

create policy "events_select_member"
on public.events
for select
to authenticated
using (
  public.is_club_member(club_id, auth.uid())
  and (
    approval_status = 'approved'
    or created_by = auth.uid()
    or public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'events.edit')
    or public.has_club_permission(club_id, auth.uid(), 'events.create')
    or public.has_club_permission(club_id, auth.uid(), 'events.approve')
  )
);

comment on policy "events_select_member" on public.events is
  'Members see approved events only; creators and permission holders see pending/rejected.';

-- ═══════════════════════════════════════════════════════════════════════════
-- 7. announcements SELECT: members need published + approved; approvers see pending
-- ═══════════════════════════════════════════════════════════════════════════

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
      and approval_status = 'approved'
    )
    or public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'announcements.edit')
    or public.has_club_permission(club_id, auth.uid(), 'announcements.approve')
    or created_by = auth.uid()
  )
);

comment on policy "announcements_select_visible" on public.announcements is
  'Members see published posts that are approval-approved; authors and editors/approvers see drafts and pending.';

-- ═══════════════════════════════════════════════════════════════════════════
-- 8. Reads / poll votes: only on approved member-visible announcements
-- ═══════════════════════════════════════════════════════════════════════════

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
        and a.approval_status = 'approved'
        and (a.scheduled_for is null or a.scheduled_for <= now())
    )
  );

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
        and a.approval_status = 'approved'
        and (a.scheduled_for is null or a.scheduled_for <= now())
        and a.poll_question is not null
        and a.poll_options is not null
        and jsonb_typeof(a.poll_options) = 'array'
    )
  );

-- poll_votes_update_self — same guard in with_check (see 042)
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
        and a.approval_status = 'approved'
        and (a.scheduled_for is null or a.scheduled_for <= now())
        and a.poll_question is not null
    )
  );
