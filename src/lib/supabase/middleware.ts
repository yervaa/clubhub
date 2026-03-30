import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { filterSupabaseCookiesFromHeader, isInvalidRefreshSessionError } from "@/lib/supabase/auth-errors";
import { getSupabaseEnv } from "@/lib/supabase/env";

function nextWithOptionalStrippedCookies(request: NextRequest): NextResponse {
  const raw = request.headers.get("cookie");
  const filtered = filterSupabaseCookiesFromHeader(raw);
  const headers = new Headers(request.headers);
  if (filtered) headers.set("cookie", filtered);
  else headers.delete("cookie");

  const downstream = new NextRequest(request.url, { headers });

  const response = NextResponse.next({
    request: downstream,
  });

  for (const { name } of request.cookies.getAll()) {
    if (name.startsWith("sb-")) {
      response.cookies.set(name, "", { maxAge: 0, path: "/" });
    }
  }

  return response;
}

export async function updateSession(request: NextRequest) {
  const { url, anonKey } = getSupabaseEnv();

  let response = NextResponse.next({
    request,
  });

  const supabase = createServerClient(url, anonKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));

        response = NextResponse.next({
          request,
        });

        cookiesToSet.forEach(({ name, value, options }) => {
          response.cookies.set(name, value, options);
        });
      },
    },
  });

  const { error } = await supabase.auth.getUser();

  if (error && isInvalidRefreshSessionError(error)) {
    return nextWithOptionalStrippedCookies(request);
  }

  return response;
}
