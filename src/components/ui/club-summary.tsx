"use client";

import { ClubDetail } from "@/lib/clubs/queries";

type ClubSummaryProps = {
  club: ClubDetail;
};

export function ClubSummary({ club }: ClubSummaryProps) {
  const memberCount = club.memberCount;

  // Find next upcoming event
  const now = new Date();
  const nextEvent = club.events
    .filter(event => event.eventDateRaw > now)
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0];

  // Find most recent announcement
  const recentAnnouncement = club.announcements
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];

  // Check for coming soon events (within 48 hours)
  const comingSoonEvents = club.events.filter(event => {
    const timeDiff = event.eventDateRaw.getTime() - now.getTime();
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    return hoursDiff > 0 && hoursDiff <= 48;
  });

  const nextComingSoonEvent = comingSoonEvents
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0];

  const totalGoingCount = club.events.reduce((sum, event) => sum + event.rsvpCounts.yes, 0);
  const totalRsvpCount = club.events.reduce(
    (sum, event) => sum + event.rsvpCounts.yes + event.rsvpCounts.no + event.rsvpCounts.maybe,
    0,
  );
  const engagementScore = club.announcements.length * 2 + totalRsvpCount;

  const engagement = (() => {
    if (engagementScore >= 12) {
      return {
        label: "High",
        copy: "Strong activity across updates and RSVPs.",
        tone: "text-emerald-700",
        badge: "bg-emerald-100 text-emerald-800",
      };
    }

    if (engagementScore >= 5) {
      return {
        label: "Building",
        copy: "Members are starting to engage.",
        tone: "text-blue-700",
        badge: "bg-blue-100 text-blue-800",
      };
    }

    return {
      label: "New",
      copy: "More posts and RSVPs will grow activity.",
      tone: "text-slate-700",
      badge: "bg-slate-100 text-slate-700",
    };
  })();

  return (
    <>
      {/* Coming Soon Alert */}
      {nextComingSoonEvent && (
        <div className="rounded-lg border border-orange-200 bg-gradient-to-r from-orange-50 to-yellow-50 p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-orange-100">
              <svg className="h-4 w-4 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-orange-900">Coming Soon</p>
              <p className="text-sm text-orange-800">
                {nextComingSoonEvent.title} - {nextComingSoonEvent.eventDate}
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <div className="card-surface p-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-100">
              <svg className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-slate-600">Next Event</p>
              <p className="text-lg font-semibold text-slate-900">
                {nextEvent ? nextEvent.title : "No upcoming events"}
              </p>
              {nextEvent && (
                <p className="text-sm text-slate-500">{nextEvent.eventDate}</p>
              )}
            </div>
          </div>
        </div>

        <div className="card-surface p-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-100">
              <svg className="h-5 w-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-slate-600">Latest Announcement</p>
              <p className="text-lg font-semibold text-slate-900">
                {recentAnnouncement ? recentAnnouncement.title : "No announcements yet"}
              </p>
              {recentAnnouncement && (
                <p className="text-sm text-slate-500">{recentAnnouncement.createdAt}</p>
              )}
            </div>
          </div>
        </div>

        <div className="card-surface p-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-100">
              <svg className="h-5 w-5 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium text-slate-600">Total Members</p>
              <p className="text-lg font-semibold text-slate-900">{memberCount}</p>
              <p className="text-sm text-slate-500">
                {memberCount === 0 ? "Invite your first members." : memberCount <= 5 ? "Growing your community!" : "Active participants"}
              </p>
            </div>
          </div>
        </div>

        <div className="card-surface p-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-100">
              <svg className="h-5 w-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium text-slate-600">Engagement</p>
                <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${engagement.badge}`}>
                  {engagement.label}
                </span>
              </div>
              <p className="text-lg font-semibold text-slate-900">{totalGoingCount} going</p>
              <p className={`text-sm ${engagement.tone}`}>{engagement.copy}</p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
