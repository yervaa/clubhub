-- Stripe-backed club dues: payment requests + per-member payment rows (one-time Checkout).

insert into public.permissions (key, description)
values ('dues.manage', 'Create club dues payment requests and view all Stripe payment records for the club')
on conflict (key) do nothing;

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
cross join public.permissions p
where cr.name = 'President'
  and cr.is_system = true
  and p.key = 'dues.manage'
  and not exists (
    select 1 from public.role_permissions rp2
    where rp2.role_id = cr.id and rp2.permission_id = p.id
  );

insert into public.role_permissions (role_id, permission_id)
select cr.id, p.id
from public.club_roles cr
cross join public.permissions p
where cr.name = 'Officer'
  and cr.is_system = true
  and p.key = 'dues.manage'
  and not exists (
    select 1 from public.role_permissions rp2
    where rp2.role_id = cr.id and rp2.permission_id = p.id
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- dues: one payment request per club (title, amount, optional due date)
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.dues (
  id            uuid        primary key default gen_random_uuid(),
  club_id       uuid        not null references public.clubs(id) on delete cascade,
  title         text        not null,
  description   text        not null default '',
  amount_cents  integer     not null,
  currency      text        not null default 'USD',
  due_date      date        null,
  created_by    uuid        not null references public.profiles(id) on delete restrict,
  created_at    timestamptz not null default now(),
  canceled_at   timestamptz null,
  constraint dues_title_max check (char_length(title) <= 200),
  constraint dues_description_max check (char_length(description) <= 4000),
  constraint dues_amount_cents_positive check (amount_cents > 0),
  constraint dues_currency_max check (char_length(currency) <= 8)
);

comment on table public.dues is
  'Stripe-eligible dues request (one-time Checkout). Soft-canceled via canceled_at.';

create index if not exists idx_dues_club_created on public.dues (club_id, created_at desc);

-- ═══════════════════════════════════════════════════════════════════════════
-- dues_payments: one row per member per dues item (checkout session lifecycle)
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.dues_payments (
  id                         uuid        primary key default gen_random_uuid(),
  dues_id                    uuid        not null references public.dues(id) on delete restrict,
  club_id                    uuid        not null references public.clubs(id) on delete cascade,
  user_id                    uuid        not null references public.profiles(id) on delete cascade,
  amount_cents               integer     not null,
  currency                   text        not null default 'USD',
  status                     text        not null default 'pending',
  stripe_checkout_session_id text        null,
  stripe_payment_intent_id   text        null,
  paid_at                    timestamptz null,
  created_at                 timestamptz not null default now(),
  constraint dues_payments_status_check
    check (status in ('pending', 'paid', 'failed', 'canceled')),
  constraint dues_payments_one_per_user unique (dues_id, user_id),
  constraint dues_payments_amount_positive check (amount_cents > 0),
  constraint dues_payments_currency_max check (char_length(currency) <= 8)
);

comment on table public.dues_payments is
  'Per-member Stripe Checkout payment for a dues item. Webhook marks paid; members insert pending via checkout action.';

create unique index if not exists dues_payments_stripe_session_uidx
  on public.dues_payments (stripe_checkout_session_id)
  where stripe_checkout_session_id is not null;

create index if not exists idx_dues_payments_club on public.dues_payments (club_id);
create index if not exists idx_dues_payments_dues on public.dues_payments (dues_id);

-- Paid + intent optional uniqueness for idempotent webhook handling
create unique index if not exists dues_payments_stripe_pi_uidx
  on public.dues_payments (stripe_payment_intent_id)
  where stripe_payment_intent_id is not null;

-- ═══════════════════════════════════════════════════════════════════════════
-- RLS: dues
-- ═══════════════════════════════════════════════════════════════════════════

alter table public.dues enable row level security;

drop policy if exists "dues_select_club" on public.dues;
create policy "dues_select_club"
  on public.dues
  for select
  to authenticated
  using (
    public.is_club_member(club_id, auth.uid())
    and (
      canceled_at is null
      or public.has_club_permission(club_id, auth.uid(), 'dues.manage')
      or public.is_club_officer(club_id, auth.uid())
    )
  );

drop policy if exists "dues_insert_manage" on public.dues;
create policy "dues_insert_manage"
  on public.dues
  for insert
  to authenticated
  with check (
    auth.uid() = created_by
    and public.is_club_member(club_id, auth.uid())
    and (
      public.has_club_permission(club_id, auth.uid(), 'dues.manage')
      or public.is_club_officer(club_id, auth.uid())
    )
  );

drop policy if exists "dues_update_manage" on public.dues;
create policy "dues_update_manage"
  on public.dues
  for update
  to authenticated
  using (
    public.has_club_permission(club_id, auth.uid(), 'dues.manage')
    or public.is_club_officer(club_id, auth.uid())
  )
  with check (
    public.has_club_permission(club_id, auth.uid(), 'dues.manage')
    or public.is_club_officer(club_id, auth.uid())
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- RLS: dues_payments (members: own row; managers: all in club)
-- ═══════════════════════════════════════════════════════════════════════════

alter table public.dues_payments enable row level security;

drop policy if exists "dues_payments_select" on public.dues_payments;
create policy "dues_payments_select"
  on public.dues_payments
  for select
  to authenticated
  using (
    (
      user_id = auth.uid()
      and public.is_club_member(club_id, auth.uid())
    )
    or public.has_club_permission(club_id, auth.uid(), 'dues.manage')
    or public.is_club_officer(club_id, auth.uid())
  );

drop policy if exists "dues_payments_insert_self" on public.dues_payments;
create policy "dues_payments_insert_self"
  on public.dues_payments
  for insert
  to authenticated
  with check (
    user_id = auth.uid()
    and public.is_club_member(club_id, auth.uid())
    and status = 'pending'
    and exists (
      select 1
      from public.dues d
      where d.id = dues_id
        and d.club_id = club_id
        and d.canceled_at is null
    )
  );

-- No client updates — Stripe webhook uses service role.
