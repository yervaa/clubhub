import { NextResponse } from "next/server";
import { dispatchEventReminders } from "@/lib/announcements/event-reminders";

function authorize(request: Request): boolean {
  const secret = process.env.CRON_SECRET?.trim();
  if (!secret) {
    return false;
  }
  const auth = request.headers.get("authorization");
  if (auth === `Bearer ${secret}`) {
    return true;
  }
  const url = new URL(request.url);
  return url.searchParams.get("secret") === secret;
}

export async function GET(request: Request) {
  if (!authorize(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { notified } = await dispatchEventReminders();
    return NextResponse.json({ ok: true, notified });
  } catch (e) {
    console.error("[cron:event-reminders]", e);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
