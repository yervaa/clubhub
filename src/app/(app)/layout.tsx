import { AppShell } from "@/components/layout/app-shell";
import { createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";

type AppLayoutProps = {
  children: React.ReactNode;
};

export default async function AppLayout({ children }: AppLayoutProps) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  return <AppShell>{children}</AppShell>;
}
