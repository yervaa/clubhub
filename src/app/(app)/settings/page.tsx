import Link from "next/link";
import { PageIntro } from "@/components/ui/page-intro";
import { CardSection, SectionHeader } from "@/components/ui/page-patterns";
import { getCurrentUserClubs } from "@/lib/clubs/queries";
import { createClient } from "@/lib/supabase/server";

export default async function SettingsPage() {
  const [clubs, supabase] = await Promise.all([getCurrentUserClubs(), createClient()]);
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const manageableClubs = clubs.filter((club) => club.role === "officer");

  return (
    <section className="space-y-4 lg:space-y-6">
      <PageIntro
        kicker="Account"
        title="Settings"
        description="Manage your account context and jump into club-level settings for the clubs you help run."
      />

      <CardSection>
        <SectionHeader kicker="Profile" title="Signed in as" />
        <p className="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
          {user?.email ?? "Unknown account"}
        </p>
      </CardSection>

      <CardSection>
        <SectionHeader
          kicker="Club settings"
          title="Manage clubs"
          action={<span className="badge-soft">{manageableClubs.length}</span>}
        />
        {manageableClubs.length === 0 ? (
          <p className="mt-3 text-sm text-slate-600">
            You currently do not have club management permissions.
          </p>
        ) : (
          <ul className="mt-3 space-y-2">
            {manageableClubs.map((club) => (
              <li key={club.id}>
                <Link
                  href={`/clubs/${club.id}/settings`}
                  className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5 text-sm transition hover:bg-slate-100"
                >
                  <span className="font-medium text-slate-900">{club.name}</span>
                  <span className="text-slate-500">Open</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardSection>
    </section>
  );
}
