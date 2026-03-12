import { AppSidebar } from "@/components/layout/app-sidebar";
import { Navbar } from "@/components/layout/navbar";

type AppShellProps = {
  children: React.ReactNode;
};

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <div className="mx-auto flex w-full max-w-7xl">
        <AppSidebar />
        <main className="w-full px-4 py-8 sm:px-6">{children}</main>
      </div>
    </div>
  );
}
