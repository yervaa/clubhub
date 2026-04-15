-- Club-level dues term (amount, due date, label). One row per club. Apply after 044.
-- RLS: leadership only — same predicate as public.club_member_dues.

create table if not exists public.club_dues_settings (
  club_id      uuid        not null references public.clubs(id) on delete cascade,
  label        text        not null,
  amount_cents integer     not null,
  due_date     date        not null,
  currency     text        not null default 'USD',
  updated_at   timestamptz not null default now(),
  updated_by   uuid        null references public.profiles(id) on delete set null,
  primary key (club_id),
  constraint club_dues_settings_label_max
    check (char_length(label) <= 200),
  constraint club_dues_settings_amount_cents_check
    check (amount_cents >= 0),
  constraint club_dues_settings_currency_max
    check (char_length(currency) <= 8)
);

comment on table public.club_dues_settings is
  'Current club dues term (label, amount, due date). Leadership-only via RLS; complements public.club_member_dues.';

-- ─── Audit columns (mirror club_member_dues trigger behavior) ────────────────

create or replace function public.touch_club_dues_settings()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end;
$$;

drop trigger if exists club_dues_settings_touch on public.club_dues_settings;
create trigger club_dues_settings_touch
  before insert or update on public.club_dues_settings
  for each row execute function public.touch_club_dues_settings();

-- ─── RLS (same pattern as club_member_dues) ──────────────────────────────────

alter table public.club_dues_settings enable row level security;

drop policy if exists "club_dues_settings_select" on public.club_dues_settings;
create policy "club_dues_settings_select"
  on public.club_dues_settings
  for select
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

drop policy if exists "club_dues_settings_insert" on public.club_dues_settings;
create policy "club_dues_settings_insert"
  on public.club_dues_settings
  for insert
  to authenticated
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

drop policy if exists "club_dues_settings_update" on public.club_dues_settings;
create policy "club_dues_settings_update"
  on public.club_dues_settings
  for update
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  )
  with check (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );

-- Needed when a club row is deleted: cascaded DELETEs are still checked by RLS.
-- Same officers / permission as club_member_dues_delete.
drop policy if exists "club_dues_settings_delete" on public.club_dues_settings;
create policy "club_dues_settings_delete"
  on public.club_dues_settings
  for delete
  to authenticated
  using (
    public.is_club_officer(club_id, auth.uid())
    or public.has_club_permission(club_id, auth.uid(), 'members.manage_member_dues')
  );
