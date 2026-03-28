import { AppShell } from "@/components/layout/app-shell";
import { unstable_noStore as noStore } from "next/cache";
import { createClient } from "@/lib/supabase/server";
import { getCurrentUserClubs } from "@/lib/clubs/queries";
import { redirect } from "next/navigation";

type AppLayoutProps = {
  children: React.ReactNode;
};

export default async function AppLayout({ children }: AppLayoutProps) {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const clubs = await getCurrentUserClubs();

  return <AppShell clubs={clubs}>{children}</AppShell>;
}
