import { AppSidebar } from "@/components/layout/app-sidebar";
import { Navbar } from "@/components/layout/navbar";
import type { UserClub } from "@/lib/clubs/queries";

type AppShellProps = {
  clubs: UserClub[];
  children: React.ReactNode;
};

export function AppShell({ clubs, children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar clubs={clubs} />
      <div className="mx-auto flex w-full max-w-7xl">
        <AppSidebar clubs={clubs} />
        <main className="w-full min-w-0 px-3 py-6 sm:px-4 md:py-8 lg:px-6">{children}</main>
      </div>
    </div>
  );
}
