import type { NextRequest } from "next/server";
import { updateSession } from "@/lib/supabase/middleware";

export async function middleware(request: NextRequest) {
  // #region agent log
  if (request.nextUrl.pathname.startsWith("/api/cron")) {
    fetch("http://127.0.0.1:7752/ingest/8564b646-700d-4bcb-a3b0-4286eed37fa8", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "86922c" },
      body: JSON.stringify({
        sessionId: "86922c",
        runId: "pre-fix",
        hypothesisId: "H1-H2",
        location: "middleware.ts:/api/cron",
        message: "middleware invoked for cron path",
        data: {
          pathname: request.nextUrl.pathname,
          method: request.method,
        },
        timestamp: Date.now(),
      }),
    }).catch(() => {});
  }
  // #endregion
  return updateSession(request);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
