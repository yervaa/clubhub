"use client";

import { ClubDetail } from "@/lib/clubs/queries";

type ClubSummaryProps = {
  club: ClubDetail;
};

export function ClubSummary({ club }: ClubSummaryProps) {
  // Find next upcoming event
  const now = new Date();
  const nextEvent = club.events
    .filter(event => event.eventDateRaw > now)
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0];

  // Find most recent announcement
  const recentAnnouncement = club.announcements
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];

  return (
    <div className="grid gap-4 md:grid-cols-3">
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
          <div>
            <p className="text-sm font-medium text-slate-600">Total Members</p>
            <p className="text-lg font-semibold text-slate-900">{club.members.length}</p>
            <p className="text-sm text-slate-500">Active participants</p>
          </div>
        </div>
      </div>
    </div>
  );
}