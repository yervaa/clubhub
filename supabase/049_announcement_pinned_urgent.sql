-- Announcement management enhancements: pinned + urgent flags.
-- Draft/published lifecycle continues to use existing `is_published` column.

alter table public.announcements
  add column if not exists is_pinned boolean not null default false,
  add column if not exists pinned_at timestamptz,
  add column if not exists is_urgent boolean not null default false;

comment on column public.announcements.is_pinned is
  'True when this published announcement is pinned at the top of the feed.';
comment on column public.announcements.pinned_at is
  'Timestamp used for deterministic pinned ordering (newly pinned first).';
comment on column public.announcements.is_urgent is
  'Display/notification-priority hint for high-importance announcements.';

-- Keep semantics simple and explicit: drafts cannot be pinned.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'announcements_pinned_requires_published'
      and conrelid = 'public.announcements'::regclass
  ) then
    alter table public.announcements
      add constraint announcements_pinned_requires_published
      check (not is_pinned or is_published = true);
  end if;
end $$;

create index if not exists idx_announcements_club_pin_sort
  on public.announcements (club_id, is_pinned desc, pinned_at desc, created_at desc);
