import { NextResponse } from "next/server";
import { publishDueScheduledAnnouncements } from "@/lib/announcements/publish-scheduled";

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

/**
 * Vercel Cron (see vercel.json) or any scheduler hitting this route with CRON_SECRET.
 */
export async function GET(request: Request) {
  if (!authorize(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { published } = await publishDueScheduledAnnouncements();
    return NextResponse.json({ ok: true, published });
  } catch (e) {
    console.error("[cron:publish-announcements]", e);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
