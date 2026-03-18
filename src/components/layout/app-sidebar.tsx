import Link from "next/link";

const sidebarLinks = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/clubs", label: "My Clubs" },
  { href: "/clubs/create", label: "Create Club" },
  { href: "/clubs/join", label: "Join Club" },
];

export function AppSidebar() {
  return (
    <aside className="hidden w-64 flex-none border-r border-slate-200 bg-white lg:block">
      <div className="sticky top-16 flex min-h-[calc(100vh-4rem)] flex-col p-5">
        <div className="mb-5 rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <p className="section-kicker">Workspace</p>
          <p className="mt-2 text-sm font-semibold text-slate-900">Keep your club work in one place.</p>
          <p className="mt-1 text-sm text-slate-600">Jump between your dashboard, club list, and setup actions.</p>
        </div>
        <nav className="space-y-1">
          {sidebarLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="block rounded-lg px-3 py-2.5 text-sm font-medium text-slate-700 transition hover:bg-slate-100 hover:text-slate-900"
            >
              {link.label}
            </Link>
          ))}
        </nav>
      </div>
    </aside>
  );
}
