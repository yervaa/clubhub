import Link from "next/link";
import { notFound } from "next/navigation";
import { ClubAttentionNeededSection } from "@/components/ui/club-attention-needed-section";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubOverviewPageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubOverviewPage({ params }: ClubOverviewPageProps) {
  const { clubId } = await params;
  const club = await getClubDetailForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  const memberCount = club.memberCount;
  const now = new Date();
  const nextEvent = [...club.events]
    .filter((event) => event.eventDateRaw.getTime() > now.getTime())
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0] ?? null;
  const latestAnnouncement = club.announcements[0] ?? null;

  return (
    <section className="space-y-8">
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-blue-50 p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Club Command Center</p>
          <h1 className="section-title mt-3 text-3xl md:text-4xl">{club.name}</h1>
          <p className="section-subtitle mt-4 max-w-2xl text-lg text-slate-700">{club.description}</p>

          <div className="mt-8 grid gap-6 md:grid-cols-3">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
                <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Members</p>
                <p className="text-xl font-bold text-slate-900">{memberCount}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100">
                <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Your Role</p>
                <p className="text-xl font-bold text-slate-900">{club.currentUserRole}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-purple-100">
                <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Status</p>
                <p className="text-xl font-bold text-slate-900">
                  {club.events.length > 0 ? "Active" : "Getting Started"}
                </p>
              </div>
            </div>
          </div>

          <div className="mt-8 flex flex-col gap-4 sm:flex-row sm:gap-3">
            {club.currentUserRole === "officer" ? (
              <Link href={`/clubs/${club.id}/members#invite-members`} className="btn-primary px-6 py-3 text-base font-semibold">
                Invite Members
              </Link>
            ) : null}
            {club.currentUserRole === "officer" ? (
              <Link href={`/clubs/${club.id}/events#create-event`} className="btn-secondary px-6 py-3 text-base font-semibold">
                Create Event
              </Link>
            ) : null}
          </div>
        </div>
      </header>

      <section className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-900">Important Now</h2>
          <p className="mt-2 text-slate-600">Key updates and priorities for your club</p>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <div className="card-surface border-l-4 border-blue-500 p-6">
            <div className="flex items-start gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-100">
                <svg className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-600">Next Event</p>
                <p className="mt-1 text-lg font-semibold text-slate-900">{nextEvent ? nextEvent.title : "No upcoming events"}</p>
                {nextEvent ? (
                  <p className="mt-1 text-sm text-slate-500">{nextEvent.eventDate} · {nextEvent.location}</p>
                ) : (
                  <p className="mt-1 text-sm text-slate-500">Schedule your first meeting on the Events page.</p>
                )}
              </div>
            </div>
          </div>

          <div className="card-surface border-l-4 border-amber-500 p-6">
            <div className="flex items-start gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-100">
                <svg className="h-5 w-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                </svg>
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-600">Latest Announcement</p>
                <p className="mt-1 text-lg font-semibold text-slate-900">{latestAnnouncement ? latestAnnouncement.title : "No announcements yet"}</p>
                {latestAnnouncement ? (
                  <p className="mt-1 text-sm text-slate-500 line-clamp-2">{latestAnnouncement.content}</p>
                ) : (
                  <p className="mt-1 text-sm text-slate-500">Post your first update on the Announcements page.</p>
                )}
              </div>
            </div>
          </div>

          <div className="card-surface border-l-4 border-green-500 p-6">
            <div className="flex items-start gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-100">
                <svg className="h-5 w-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-600">Key Stats</p>
                <p className="mt-1 text-lg font-semibold text-slate-900">{club.events.length} events · {club.announcements.length} updates</p>
                <p className="mt-1 text-sm text-slate-500">{club.totalTrackedEvents} tracked attendance events · {club.clubAverageAttendance}% average attendance</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {club.currentUserRole === "officer" ? (
        <ClubAttentionNeededSection clubId={club.id} alerts={club.attentionAlerts} />
      ) : null}
    </section>
  );
}
