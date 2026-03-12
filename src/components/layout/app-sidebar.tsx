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
        <p className="mb-3 px-2 text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">
          Workspace
        </p>
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
