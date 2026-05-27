import { AppShellHeader } from "@/components/layout/app-shell-header";
import { AppSidebar } from "@/components/layout/app-sidebar";
import type { UserClub } from "@/lib/clubs/queries";
import { getRecentNotifications, getUnreadNotificationCount } from "@/lib/notifications/queries";
import { sanitizeInlineText } from "@/lib/sanitize";
import { createClient } from "@/lib/supabase/server";

type AppShellProps = {
  clubs: UserClub[];
  children: React.ReactNode;
};

export async function AppShell({ clubs, children }: AppShellProps) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const [notifications, unreadCount, profileResult] = user
    ? await Promise.all([
        getRecentNotifications(10),
        getUnreadNotificationCount(),
        supabase.from("profiles").select("full_name").eq("id", user.id).maybeSingle(),
      ])
    : [[], 0, { data: null }];

  const metaName =
    typeof user?.user_metadata?.full_name === "string"
      ? sanitizeInlineText(user.user_metadata.full_name).slice(0, 80)
      : "";
  const profileName = profileResult.data?.full_name?.trim() || metaName;
  const userDisplayLabel = profileName || user?.email || "Account";

  return (
    <div className="app-shell flex min-h-screen flex-row">
      <AppSidebar />
      <div className="app-shell-main flex min-h-screen min-w-0 flex-1 flex-col">
        <AppShellHeader
          clubs={clubs}
          unreadCount={unreadCount}
          notifications={notifications}
          userDisplayLabel={userDisplayLabel}
        />
        <main className="app-page-main flex-1 overflow-y-auto px-3 pb-24 pt-4 sm:px-4 sm:pb-8 md:px-6 md:pt-6">
          {children}
        </main>
      </div>
    </div>
  );
}
