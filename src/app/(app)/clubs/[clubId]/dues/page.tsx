import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { cancelStripeDuesAction, createStripeDuesAction, startDuesCheckoutAction } from "@/app/(app)/clubs/dues-actions";
import { CardSection } from "@/components/ui/page-patterns";
import { PageIntro } from "@/components/ui/page-intro";
import { canManageClubStripeDues } from "@/lib/clubs/dues-permissions";
import { formatClubDuesDueDateLabel, formatClubDuesMoney } from "@/lib/clubs/dues-display";
import { createClient } from "@/lib/supabase/server";

type ClubDuesPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    success?: string;
    error?: string;
    canceled?: string;
    session_id?: string;
  }>;
};

export default async function ClubDuesPage({ params, searchParams }: ClubDuesPageProps) {
  const { clubId } = await params;
  const query = await searchParams;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: membership } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) notFound();

  const canManage = await canManageClubStripeDues(user.id, clubId);

  const { data: club } = await supabase.from("clubs").select("name, status").eq("id", clubId).maybeSingle();
  if (!club) notFound();

  const { count: activeMemberCount } = await supabase
    .from("club_members")
    .select("user_id", { count: "exact", head: true })
    .eq("club_id", clubId)
    .eq("membership_status", "active");

  const activeTotal = activeMemberCount ?? 0;

  const duesSelect =
    "id, title, description, amount_cents, currency, due_date, created_at, canceled_at" as const;

  const { data: duesRows } = canManage
    ? await supabase
        .from("dues")
        .select(duesSelect)
        .eq("club_id", clubId)
        .order("created_at", { ascending: false })
    : await supabase
        .from("dues")
        .select(duesSelect)
        .eq("club_id", clubId)
        .is("canceled_at", null)
        .order("created_at", { ascending: false });

  const { data: myPayments } = await supabase
    .from("dues_payments")
    .select("dues_id, status, paid_at, amount_cents")
    .eq("club_id", clubId)
    .eq("user_id", user.id);

  const myByDues = new Map((myPayments ?? []).map((p) => [p.dues_id, p]));

  const duesIds = (duesRows ?? []).map((d) => d.id);
  const paymentsByDuesId = new Map<string, { user_id: string; status: string; paid_at: string | null; amount_cents: number }[]>();
  const profileById = new Map<string, { full_name: string | null; email: string | null }>();

  if (duesIds.length > 0) {
    const { data: allPay } = await supabase
      .from("dues_payments")
      .select("dues_id, user_id, status, paid_at, amount_cents")
      .eq("club_id", clubId)
      .in("dues_id", duesIds);

    for (const row of allPay ?? []) {
      const list = paymentsByDuesId.get(row.dues_id) ?? [];
      list.push(row);
      paymentsByDuesId.set(row.dues_id, list);
    }

    if (canManage) {
      const paidUserIds = [...new Set((allPay ?? []).filter((p) => p.status === "paid").map((p) => p.user_id))];
      if (paidUserIds.length > 0) {
        const { data: profs } = await supabase.from("profiles").select("id, full_name, email").in("id", paidUserIds);
        for (const p of profs ?? []) {
          profileById.set(p.id, { full_name: p.full_name, email: p.email });
        }
      }
    }
  }

  const isArchived = club.status === "archived";

  return (
    <section className="space-y-6">
      <PageIntro
        kicker="Payments"
        title="Club dues"
        description={
          canManage
            ? `Create one-time dues for ${club.name}, collect via Stripe Checkout, and track who has paid.`
            : `View and pay club dues securely for ${club.name}.`
        }
      />

      {query.success ? (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-900">
          {decodeURIComponent(query.success.replace(/\+/g, " "))}
        </div>
      ) : null}
      {query.error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-900">
          {decodeURIComponent(query.error.replace(/\+/g, " "))}
        </div>
      ) : null}
      {query.canceled ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-950">
          Checkout was canceled — you can try again when ready.
        </div>
      ) : null}
      {query.session_id ? (
        <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-800">
          Thanks — if you just paid, your status updates in a few seconds after Stripe confirms the payment.
        </div>
      ) : null}

      {canManage && !isArchived ? (
        <CardSection className="border border-slate-200/90">
          <h2 className="text-lg font-semibold text-slate-900">Create dues</h2>
          <p className="mt-1 text-sm text-slate-600">
            Members receive a notification (if enabled) and can pay from this page. Currency is USD for this version.
          </p>
          <form action={createStripeDuesAction} className="mt-4 max-w-xl space-y-3">
            <input type="hidden" name="club_id" value={clubId} />
            <input type="hidden" name="currency" value="USD" />
            <div>
              <label htmlFor="dues-title" className="mb-1 block text-xs font-medium text-slate-700">
                Title
              </label>
              <input
                id="dues-title"
                name="title"
                type="text"
                required
                minLength={2}
                maxLength={200}
                className="input-control min-h-10 w-full"
                placeholder="e.g. Spring semester dues"
              />
            </div>
            <div>
              <label htmlFor="dues-desc" className="mb-1 block text-xs font-medium text-slate-700">
                Description (optional)
              </label>
              <textarea
                id="dues-desc"
                name="description"
                rows={3}
                maxLength={4000}
                className="input-control w-full resize-y text-sm"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="dues-amount" className="mb-1 block text-xs font-medium text-slate-700">
                  Amount (USD)
                </label>
                <input
                  id="dues-amount"
                  name="amount"
                  type="text"
                  inputMode="decimal"
                  required
                  className="input-control min-h-10 w-full"
                  placeholder="20.00"
                />
              </div>
              <div>
                <label htmlFor="dues-due" className="mb-1 block text-xs font-medium text-slate-700">
                  Due date (optional)
                </label>
                <input id="dues-due" name="due_date" type="date" className="input-control min-h-10 w-full" />
              </div>
            </div>
            <button type="submit" className="btn-primary min-h-10 text-sm">
              Publish dues
            </button>
          </form>
        </CardSection>
      ) : null}

      {canManage ? (
        <CardSection className="border border-slate-200/90">
          <h2 className="text-lg font-semibold text-slate-900">Treasurer overview</h2>
          <p className="mt-1 text-sm text-slate-600">
            Active members in roster: <strong>{activeTotal}</strong>. Expected totals assume each active member owes one
            payment per open dues item.
          </p>
        </CardSection>
      ) : null}

      <CardSection className="border border-slate-200/90">
        <h2 className="text-lg font-semibold text-slate-900">{canManage ? "All dues" : "Your dues"}</h2>
        {!duesRows || duesRows.length === 0 ? (
          <p className="mt-3 text-sm text-slate-600">{canManage ? "No dues requests yet." : "No open dues right now."}</p>
        ) : (
          <ul className="mt-4 space-y-4">
            {duesRows.map((d) => {
              const mine = myByDues.get(d.id);
              const isPaid = mine?.status === "paid";
              const isPending = mine?.status === "pending";
              const payments = paymentsByDuesId.get(d.id) ?? [];
              const paidRows = payments.filter((p) => p.status === "paid");
              const collectedCents = paidRows.reduce((sum, p) => sum + p.amount_cents, 0);
              const expectedCents = d.canceled_at ? 0 : activeTotal * d.amount_cents;
              const canceled = Boolean(d.canceled_at);

              return (
                <li
                  key={d.id}
                  className={`rounded-xl border px-4 py-3 ${canceled ? "border-slate-200 bg-slate-50" : "border-slate-200 bg-white"}`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-semibold text-slate-900">
                        {d.title}
                        {canceled ? (
                          <span className="ml-2 rounded-full bg-slate-200 px-2 py-0.5 text-[11px] font-semibold text-slate-700">
                            Canceled
                          </span>
                        ) : null}
                      </p>
                      {d.description?.trim() ? (
                        <p className="mt-1 whitespace-pre-wrap text-sm text-slate-600">{d.description}</p>
                      ) : null}
                      <p className="mt-2 text-sm text-slate-700">
                        <span className="font-medium">{formatClubDuesMoney(d.amount_cents, d.currency ?? "USD")}</span>
                        {d.due_date ? (
                          <>
                            <span className="text-slate-300"> · </span>
                            Due {formatClubDuesDueDateLabel(d.due_date)}
                          </>
                        ) : null}
                      </p>
                    </div>
                    {!canceled && !canManage ? (
                      <div className="shrink-0">
                        {isPaid ? (
                          <span className="inline-flex rounded-full bg-emerald-100 px-3 py-1 text-xs font-semibold text-emerald-900">
                            Paid
                            {mine?.paid_at
                              ? ` · ${new Date(mine.paid_at).toLocaleDateString(undefined, { month: "short", day: "numeric" })}`
                              : ""}
                          </span>
                        ) : (
                          <form action={startDuesCheckoutAction}>
                            <input type="hidden" name="club_id" value={clubId} />
                            <input type="hidden" name="dues_id" value={d.id} />
                            <button type="submit" className="btn-primary min-h-10 text-xs" disabled={isArchived}>
                              Pay with Stripe
                            </button>
                          </form>
                        )}
                        {isPending ? (
                          <p className="mt-1 max-w-[12rem] text-[11px] text-slate-500">Payment processing — refresh shortly.</p>
                        ) : null}
                      </div>
                    ) : null}
                  </div>

                  {canManage ? (
                    <div className="mt-3 border-t border-slate-100 pt-3 text-sm text-slate-700">
                      {!canceled ? (
                        <p>
                          Collected:{" "}
                          <strong className="tabular-nums">{formatClubDuesMoney(collectedCents, d.currency ?? "USD")}</strong>
                          {" · "}
                          Expected (if everyone pays):{" "}
                          <strong className="tabular-nums">{formatClubDuesMoney(expectedCents, d.currency ?? "USD")}</strong>
                          {" · "}
                          Paid: <strong>{paidRows.length}</strong> / {activeTotal} active members
                        </p>
                      ) : (
                        <p className="text-slate-600">Canceled — existing payments remain on record.</p>
                      )}
                      {paidRows.length > 0 ? (
                        <ul className="mt-2 space-y-1 text-sm text-slate-600">
                          {paidRows.map((p) => {
                            const pr = profileById.get(p.user_id);
                            const label = pr?.full_name?.trim() || pr?.email?.trim() || p.user_id.slice(0, 8);
                            return (
                              <li key={p.user_id}>
                                Paid · {label}
                                {p.paid_at ? ` · ${new Date(p.paid_at).toLocaleString()}` : ""}
                              </li>
                            );
                          })}
                        </ul>
                      ) : !canceled ? (
                        <p className="mt-2 text-sm text-slate-500">No payments yet.</p>
                      ) : null}
                      {!canceled && !isArchived ? (
                        <form action={cancelStripeDuesAction} className="mt-3">
                          <input type="hidden" name="club_id" value={clubId} />
                          <input type="hidden" name="dues_id" value={d.id} />
                          <button
                            type="submit"
                            className="text-xs font-semibold text-amber-800 underline decoration-amber-300"
                            formNoValidate
                          >
                            Cancel this dues request (stops new payments)
                          </button>
                        </form>
                      ) : null}
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </CardSection>

      <p className="text-center text-xs text-slate-500">
        Payments are processed by Stripe. ClubHub does not store card numbers.{" "}
        <Link href="/settings" className="font-semibold text-violet-700 underline">
          Notification settings
        </Link>
      </p>
    </section>
  );
}
