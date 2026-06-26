-- ─── 056: Harden dues_payments self-insert (amount/currency must match dues) ──
-- Defense-in-depth for the Stripe dues flow. The checkout server action already
-- copies amount_cents / currency from the dues row, but the RLS insert policy
-- from 053 did not constrain them, so a direct (anon-key) self-insert could
-- create a pending payment row with an arbitrary amount/currency. The Stripe
-- charge is always server-derived, so this never enabled underpayment, but a
-- mismatched row breaks webhook reconciliation. This policy forces the inserted
-- amount_cents / currency to equal the linked dues row.
--
-- Column/policy names match migration 053:
--   table  public.dues_payments  (user_id, club_id, dues_id, status, amount_cents, currency)
--   table  public.dues          (id, club_id, amount_cents, currency, canceled_at)  -- soft-cancel via canceled_at
--   policy "dues_payments_insert_self"
--
-- Idempotent (drop + recreate). Service-role writes bypass RLS and are unaffected.

begin;

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
        and d.amount_cents = dues_payments.amount_cents
        and coalesce(d.currency, 'usd') = coalesce(dues_payments.currency, 'usd')
    )
  );

commit;
