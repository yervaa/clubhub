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
  // #region agent log
  fetch("http://127.0.0.1:7752/ingest/8564b646-700d-4bcb-a3b0-4286eed37fa8", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "86922c" },
    body: JSON.stringify({
      sessionId: "86922c",
      runId: "pre-fix",
      hypothesisId: "H3",
      location: "event-reminders/route.ts:GET",
      message: "GET handler entered",
      data: {
        pathname: (() => {
          try {
            return new URL(request.url).pathname;
          } catch {
            return "invalid-url";
          }
        })(),
      },
      timestamp: Date.now(),
    }),
  }).catch(() => {});
  // #endregion
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
