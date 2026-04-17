import { revalidatePath } from "next/cache";
import { NextResponse } from "next/server";
import { createBulkNotifications, createNotification } from "@/lib/notifications/create-notification";
import { listPermissionHolderIds } from "@/lib/clubs/dues-permissions";
import { getStripe } from "@/lib/stripe/server";
import { createAdminClient } from "@/lib/supabase/admin";
import type Stripe from "stripe";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const rawBody = await request.text();
  const sig = request.headers.get("stripe-signature");
  const secret = process.env.STRIPE_WEBHOOK_SECRET?.trim();
  if (!secret) {
    console.error("[stripe webhook] STRIPE_WEBHOOK_SECRET is not set");
    return NextResponse.json({ error: "Server misconfiguration" }, { status: 500 });
  }
  if (!sig) {
    return NextResponse.json({ error: "Missing stripe-signature" }, { status: 400 });
  }

  let event: Stripe.Event;
  try {
    const stripe = getStripe();
    event = stripe.webhooks.constructEvent(rawBody, sig, secret);
  } catch (err) {
    console.error("[stripe webhook] signature verification failed", err);
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    await handleCheckoutSessionCompleted(event.data.object as Stripe.Checkout.Session);
  }

  return NextResponse.json({ received: true });
}

async function handleCheckoutSessionCompleted(session: Stripe.Checkout.Session) {
  if (session.mode !== "payment") {
    return;
  }

  const sessionId = session.id;
  const amountTotal = session.amount_total;
  const paymentIntentRaw = session.payment_intent;
  const paymentIntentId =
    typeof paymentIntentRaw === "string" ? paymentIntentRaw : paymentIntentRaw && "id" in paymentIntentRaw
      ? paymentIntentRaw.id
      : null;

  const admin = createAdminClient();
  const { data: row, error } = await admin
    .from("dues_payments")
    .select("id, status, user_id, club_id, dues_id, amount_cents")
    .eq("stripe_checkout_session_id", sessionId)
    .maybeSingle();

  if (error || !row) {
    console.warn("[stripe webhook] no dues_payments row for session", sessionId, error?.message);
    return;
  }

  if (row.status === "paid") {
    return;
  }

  const metaDuesId = session.metadata?.dues_id;
  if (metaDuesId && metaDuesId !== row.dues_id) {
    console.error("[stripe webhook] dues_id metadata mismatch", sessionId);
    return;
  }

  const metaUser = session.metadata?.user_id;
  if (metaUser && metaUser !== row.user_id) {
    console.error("[stripe webhook] user_id metadata mismatch", sessionId);
    return;
  }

  if (amountTotal != null && amountTotal !== row.amount_cents) {
    console.error("[stripe webhook] amount mismatch", sessionId, amountTotal, row.amount_cents);
    return;
  }

  const paidAt = new Date().toISOString();
  const { data: updated, error: upErr } = await admin
    .from("dues_payments")
    .update({
      status: "paid",
      paid_at: paidAt,
      stripe_payment_intent_id: paymentIntentId,
    })
    .eq("id", row.id)
    .eq("status", "pending")
    .select("id")
    .maybeSingle();

  if (upErr) {
    console.error("[stripe webhook] update failed", upErr.message);
    return;
  }

  if (!updated) {
    const { data: already } = await admin
      .from("dues_payments")
      .select("id")
      .eq("id", row.id)
      .eq("status", "paid")
      .maybeSingle();
    if (already) {
      return;
    }
    console.warn("[stripe webhook] no row updated and not already paid", row.id);
    return;
  }

  await createNotification({
    userId: row.user_id,
    clubId: row.club_id,
    type: "dues.paid",
    title: "Payment received",
    body: "Your club dues payment was processed successfully.",
    href: `/clubs/${row.club_id}/dues`,
    metadata: { dues_id: row.dues_id, payment_id: row.id },
  });

  const treasurerIds = await listPermissionHolderIds(row.club_id, "dues.manage");
  const recipients = treasurerIds.filter((id) => id !== row.user_id);
  if (recipients.length > 0) {
    const { data: profile } = await admin.from("profiles").select("full_name").eq("id", row.user_id).maybeSingle();
    const name = profile?.full_name?.trim() || "A member";
    await createBulkNotifications(
      recipients.map((userId) => ({
        userId,
        clubId: row.club_id,
        type: "dues.received" as const,
        title: "Dues payment received",
        body: `${name} completed a dues payment.`,
        href: `/clubs/${row.club_id}/dues`,
        metadata: { dues_id: row.dues_id },
      })),
    );
  }

  revalidatePath(`/clubs/${row.club_id}/dues`);
  revalidatePath(`/clubs/${row.club_id}`);
}
