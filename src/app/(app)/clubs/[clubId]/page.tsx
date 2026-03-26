import { notFound } from "next/navigation";
import {
  createAnnouncementAction,
  createEventAction,
  removeMemberAction,
  updateMemberRoleAction,
  upsertRsvpAction,
} from "@/app/(app)/clubs/actions";
import { GettingStartedChecklist } from "@/components/ui/getting-started-checklist";
import { AnnouncementGenerator } from "@/components/ui/announcement-generator";
import { AttendanceChecklist } from "@/components/ui/attendance-checklist";
import { ClubSummary } from "@/components/ui/club-summary";
import { CopyJoinCodeButton } from "@/components/ui/copy-join-code-button";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
import { MemberInvite } from "@/components/ui/member-invite";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    annError?: string;
    annSuccess?: string;
    eventError?: string;
    eventSuccess?: string;
    rsvpError?: string;
    rsvpSuccess?: string;
    memberError?: string;
    memberSuccess?: string;
    attendanceError?: string;
    attendanceSuccess?: string;
  }>;
};

type NextBestAction = {
  title: string;
  copy: string;
  buttonLabel: string;
  href?: string;
  inputSelector?: string;
};

function getLatestAnnouncement(club: Awaited<ReturnType<typeof getClubDetailForCurrentUser>> extends infer T ? NonNullable<T> : never) {
  return club.announcements[0] ?? null;
}

function getRelatedEventForAnnouncement(
  club: Awaited<ReturnType<typeof getClubDetailForCurrentUser>> extends infer T ? NonNullable<T> : never,
  announcement: NonNullable<ReturnType<typeof getLatestAnnouncement>>,
) {
  const haystack = `${announcement.title} ${announcement.content}`.toLowerCase();

  return club.events.find((event) => {
    const eventTitle = event.title.toLowerCase();
    const eventLocation = event.location.toLowerCase();

    return haystack.includes(eventTitle) || haystack.includes(eventLocation);
  }) ?? null;
}

function getNextBestAction(club: Awaited<ReturnType<typeof getClubDetailForCurrentUser>> extends infer T ? NonNullable<T> : never): NextBestAction {
  const upcomingEvent = [...club.events]
    .filter((event) => event.eventDateRaw.getTime() > Date.now())
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0];

  if (club.currentUserRole === "officer") {
    if (club.events.length === 0) {
      return {
        title: "Create your next meeting",
        copy: "Give members something concrete to join.",
        buttonLabel: "Create event",
        inputSelector: 'input[id="event_title"]',
      };
    }

    if (club.announcements.length === 0) {
      return {
        title: "Post an update",
        copy: "Set the tone with one clear announcement.",
        buttonLabel: "Post update",
        inputSelector: 'input[name="title"]',
      };
    }

    if (upcomingEvent && upcomingEvent.rsvpCounts.yes < Math.min(3, club.members.length)) {
      return {
        title: "Invite more members",
        copy: "Your next event needs a few more yes responses.",
        buttonLabel: "Open invite tools",
        href: "#invite-members",
      };
    }

    if (club.members.length <= 3) {
      return {
        title: "Invite more members",
        copy: "Share the join code and grow the club.",
        buttonLabel: "Open invite tools",
        href: "#invite-members",
      };
    }
  }

  if (upcomingEvent && !upcomingEvent.userRsvpStatus) {
    return {
      title: "RSVP to the next event",
      copy: "Let the club know if you can make it.",
      buttonLabel: "View events",
      href: "#events",
    };
  }

  if (club.announcements.length > 0) {
    return {
      title: "Catch up on updates",
      copy: "Check the latest announcement before the next meeting.",
      buttonLabel: "View announcements",
      href: "#announcements",
    };
  }

  return {
    title: "See who is in the club",
    copy: "Start with the member list and current roles.",
    buttonLabel: "View members",
    href: "#members",
  };
}

export default async function ClubPage({ params, searchParams }: ClubPageProps) {
  const { clubId } = await params;
  const query = await searchParams;
  const club = await getClubDetailForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  const nextBestAction = getNextBestAction(club);
  const latestAnnouncement = getLatestAnnouncement(club);
  const pinnedAnnouncementEvent = latestAnnouncement
    ? getRelatedEventForAnnouncement(club, latestAnnouncement)
    : null;
  const olderAnnouncements = latestAnnouncement ? club.announcements.slice(1) : [];

  return (
    <section className="space-y-8">
      <header className="card-surface p-7">
        <p className="section-kicker">Club Profile</p>
        <h1 className="section-title mt-2">{club.name}</h1>
        <p className="section-subtitle max-w-3xl">{club.description}</p>
        <div className="mt-6 grid gap-3 md:grid-cols-2">
          <div className="stat-card">
            <p className="stat-label">Your Role</p>
            <p className="stat-value text-[1.2rem]">{club.currentUserRole}</p>
            <p className="stat-copy">Your access level in this club.</p>
          </div>
          <div className="stat-card">
            <p className="stat-label">Members</p>
            <p className="stat-value text-[1.2rem]">{club.members.length}</p>
            <p className="stat-copy">People currently in this club.</p>
          </div>
        </div>
      </header>

      <ClubSummary club={club} />

      {latestAnnouncement ? (
        <div className="card-surface border-amber-200 bg-gradient-to-r from-amber-50 via-white to-orange-50 p-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div className="max-w-3xl">
              <div className="flex flex-wrap items-center gap-2">
                <span className="badge-strong">Pinned</span>
                <p className="section-kicker text-amber-700">Latest Announcement</p>
              </div>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{latestAnnouncement.title}</h2>
              <p className="mt-2 text-sm leading-6 text-slate-700">{latestAnnouncement.content}</p>
              <p className="mt-3 text-xs font-medium text-slate-500">{latestAnnouncement.createdAt}</p>
            </div>
            <div className="w-full max-w-sm rounded-xl border border-amber-200 bg-white/80 p-4">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Why it matters</p>
              {pinnedAnnouncementEvent ? (
                <>
                  <p className="mt-2 text-sm font-semibold text-slate-900">Connected to {pinnedAnnouncementEvent.title}</p>
                  <p className="mt-1 text-sm text-slate-600">{pinnedAnnouncementEvent.eventDate} · {pinnedAnnouncementEvent.location}</p>
                  <a href="#events" className="btn-secondary mt-3 inline-block text-xs">
                    View event details
                  </a>
                </>
              ) : (
                <>
                  <p className="mt-2 text-sm font-semibold text-slate-900">Most important update right now</p>
                  <p className="mt-1 text-sm text-slate-600">Members can find the key announcement here without scrolling through every post.</p>
                  <a href="#announcements" className="btn-secondary mt-3 inline-block text-xs">
                    View all announcements
                  </a>
                </>
              )}
            </div>
          </div>
        </div>
      ) : null}

      <div className="card-surface border-blue-200 bg-gradient-to-r from-blue-50 via-white to-indigo-50 p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="section-kicker">Next Best Action</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{nextBestAction.title}</h2>
            <p className="mt-1 text-sm text-slate-600">{nextBestAction.copy}</p>
          </div>
          {nextBestAction.inputSelector ? (
            <ScrollToInputButton inputSelector={nextBestAction.inputSelector} className="btn-primary whitespace-nowrap">
              {nextBestAction.buttonLabel}
            </ScrollToInputButton>
          ) : (
            <a href={nextBestAction.href} className="btn-primary whitespace-nowrap">
              {nextBestAction.buttonLabel}
            </a>
          )}
        </div>
      </div>

      <div className="card-surface p-6">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Recent Activity</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">What happened lately</h2>
            <p className="mt-1 text-sm text-slate-600">A quick feed of club movement, updates, and responses.</p>
          </div>
          <span className="badge-soft">{club.recentActivity.length} items</span>
        </div>

        {club.recentActivity.length === 0 ? (
          <div className="empty-state mt-4 p-6">
            <p className="empty-state-title">No recent activity yet.</p>
            <p className="empty-state-copy">As people join, announcements are posted, and events are scheduled, they will appear here.</p>
          </div>
        ) : (
          <div className="list-stack mt-4">
            {club.recentActivity.map((item) => (
              <article key={item.id} className="surface-subcard p-4">
                <div className="flex items-start justify-between gap-3">
                  <p className="text-sm font-medium text-slate-900">{item.message}</p>
                  <span className="whitespace-nowrap text-xs text-slate-500">{item.createdAt}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>

      {club.currentUserRole === "officer" && (
        <div id="invite-members">
          <MemberInvite joinCode={club.joinCode} membersCount={club.members.length} />
        </div>
      )}

      {club.currentUserRole === "officer" ? (
        <GettingStartedChecklist
          membersCount={club.members.length}
          announcementsCount={club.announcements.length}
          eventsCount={club.events.length}
        />
      ) : null}

      <div className="card-surface p-6" id="members">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">People</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Members</h2>
            <p className="mt-1 text-sm text-slate-600">See who is part of the club and what role they hold.</p>
          </div>
          <span className="badge-soft">{club.members.length} total</span>
        </div>
        {query.memberSuccess ? <p className="alert-success mt-4">{query.memberSuccess}</p> : null}
        {query.memberError ? <p className="alert-error mt-3">{query.memberError}</p> : null}
        {club.members.length === 0 ? (
          <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 to-slate-50 p-6">
            <p className="font-semibold text-slate-900">Share your join code</p>
            <p className="mt-1 text-sm text-slate-600">Let people join using this code:</p>
            <div className="mt-3 rounded-md bg-white p-3 border border-slate-200">
              <p className="text-center text-lg font-bold tracking-wider text-slate-900">
                {club.currentUserRole === "officer" ? club.joinCode : "Only officers see this"}
              </p>
            </div>
            {club.currentUserRole === "officer" && (
              <CopyJoinCodeButton
                joinCode={club.joinCode}
                className="btn-secondary mt-3 w-full text-xs"
              />
            )}
          </div>
        ) : (
          <ul className="list-stack mt-4">
            {club.members.map((member) => (
              <li key={member.userId} className="surface-subcard px-4 py-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate text-sm font-semibold text-slate-900">
                        {member.fullName?.trim() || member.email || member.userId}
                      </p>
                      {member.userId === club.currentUserId ? <span className="badge-soft">You</span> : null}
                    </div>
                    <p className="mt-1 truncate text-sm text-slate-600">{member.email ?? member.userId}</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={member.role === "officer" ? "badge-strong" : "badge-soft"}>{member.role}</span>
                  </div>
                </div>
                {club.currentUserRole === "officer" && member.userId !== club.currentUserId ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {member.role === "member" ? (
                      <form action={updateMemberRoleAction}>
                        <input type="hidden" name="club_id" value={club.id} />
                        <input type="hidden" name="user_id" value={member.userId} />
                        <input type="hidden" name="role" value="officer" />
                        <button type="submit" className="btn-secondary text-xs">
                          Promote to Officer
                        </button>
                      </form>
                    ) : (
                      <form action={updateMemberRoleAction}>
                        <input type="hidden" name="club_id" value={club.id} />
                        <input type="hidden" name="user_id" value={member.userId} />
                        <input type="hidden" name="role" value="member" />
                        <button type="submit" className="btn-secondary text-xs">
                          Demote to Member
                        </button>
                      </form>
                    )}
                    <form action={removeMemberAction}>
                      <input type="hidden" name="club_id" value={club.id} />
                      <input type="hidden" name="user_id" value={member.userId} />
                      <button type="submit" className="btn-secondary text-xs">
                        Remove from Club
                      </button>
                    </form>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card-surface p-6" id="announcements">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Communication</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Announcements</h2>
            <p className="mt-1 text-sm text-slate-600">Important updates for everyone in the club.</p>
          </div>
          <span className="badge-soft">{club.announcements.length} posted</span>
        </div>
        {query.annSuccess ? <p className="alert-success mt-4">{query.annSuccess}</p> : null}
        {query.annError ? <p className="alert-error mt-3">{query.annError}</p> : null}

        {club.currentUserRole === "officer" ? (
          <form action={createAnnouncementAction} className="mt-4 space-y-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4">
            <input type="hidden" name="club_id" value={club.id} />
            <div>
              <p className="text-sm font-semibold text-slate-900">Post a new update</p>
              <p className="mt-1 text-sm text-slate-600">Share meeting changes, reminders, or important news with everyone in the club.</p>
            </div>
            <AnnouncementGenerator
              titleSelector='input[name="title"]'
              contentSelector='textarea[name="content"]'
            />
            <div>
              <label htmlFor="title" className="mb-1.5 block text-sm font-medium text-slate-700">
                Title
              </label>
              <input id="title" name="title" type="text" required className="input-control" placeholder="Announcement title" />
            </div>
            <div>
              <label htmlFor="content" className="mb-1.5 block text-sm font-medium text-slate-700">
                Content
              </label>
              <textarea id="content" name="content" rows={4} required className="textarea-control" placeholder="Write your announcement..." />
            </div>
            <button type="submit" className="btn-primary">
              Post announcement
            </button>
          </form>
        ) : null}

        {club.announcements.length === 0 ? (
          <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-purple-50 to-slate-50 p-6">
            <p className="font-semibold text-slate-900">Keep your club in the loop</p>
            <p className="mt-1 text-sm text-slate-600">Post updates about meetings, schedule changes, or important info.</p>
            {club.currentUserRole === "officer" && (
              <ScrollToInputButton
                inputSelector='input[name="title"]'
                className="btn-secondary mt-3"
              >
                Create First Announcement
              </ScrollToInputButton>
            )}
          </div>
        ) : (
          <div className="list-stack mt-4">
            {olderAnnouncements.length === 0 ? (
              <div className="surface-subcard p-4">
                <p className="text-sm font-semibold text-slate-900">No older announcements yet</p>
                <p className="mt-1 text-sm text-slate-600">The latest announcement is pinned above so members see it first.</p>
              </div>
            ) : olderAnnouncements.map((announcement) => (
              <article key={announcement.id} className="surface-subcard p-4">
                <div className="flex items-start justify-between gap-3">
                  <h3 className="text-sm font-semibold text-slate-900">{announcement.title}</h3>
                  <span className="text-xs text-slate-500">{announcement.createdAt}</span>
                </div>
                <p className="mt-2 text-sm leading-6 text-slate-600">{announcement.content}</p>
              </article>
            ))}
          </div>
        )}
      </div>

      <div className="card-surface p-6" id="events">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Planning</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Events</h2>
            <p className="mt-1 text-sm text-slate-600">Track what is coming up and collect responses from members.</p>
          </div>
          <span className="badge-soft">{club.events.length} scheduled</span>
        </div>
        {query.eventSuccess ? <p className="alert-success mt-4">{query.eventSuccess}</p> : null}
        {query.eventError ? <p className="alert-error mt-3">{query.eventError}</p> : null}
        {query.rsvpSuccess ? <p className="alert-success mt-3">{query.rsvpSuccess}</p> : null}
        {query.rsvpError ? <p className="alert-error mt-3">{query.rsvpError}</p> : null}
        {query.attendanceSuccess ? <p className="alert-success mt-3">{query.attendanceSuccess}</p> : null}
        {query.attendanceError ? <p className="alert-error mt-3">{query.attendanceError}</p> : null}

        {club.currentUserRole === "officer" ? (
          <form action={createEventAction} className="mt-4 space-y-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4">
            <input type="hidden" name="club_id" value={club.id} />
            <div>
              <p className="text-sm font-semibold text-slate-900">Schedule a new event</p>
              <p className="mt-1 text-sm text-slate-600">Create a clear event card members can respond to quickly.</p>
            </div>
            <div>
              <label htmlFor="event_title" className="mb-1.5 block text-sm font-medium text-slate-700">
                Title
              </label>
              <input id="event_title" name="title" type="text" required className="input-control" placeholder="Event title" />
            </div>
            <div>
              <label htmlFor="event_description" className="mb-1.5 block text-sm font-medium text-slate-700">
                Description
              </label>
              <textarea
                id="event_description"
                name="description"
                rows={3}
                required
                className="textarea-control"
                placeholder="Describe the event..."
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="event_location" className="mb-1.5 block text-sm font-medium text-slate-700">
                  Location
                </label>
                <input
                  id="event_location"
                  name="location"
                  type="text"
                  required
                  className="input-control"
                  placeholder="Room 204"
                />
              </div>
              <div>
                <label htmlFor="event_date" className="mb-1.5 block text-sm font-medium text-slate-700">
                  Event date
                </label>
                <input id="event_date" name="event_date" type="datetime-local" required className="input-control" />
              </div>
            </div>
            <button type="submit" className="btn-primary">
              Create event
            </button>
          </form>
        ) : null}

        {club.events.length === 0 ? (
          <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-indigo-50 to-slate-50 p-6">
            <p className="font-semibold text-slate-900">Schedule your first meeting</p>
            <p className="mt-1 text-sm text-slate-600">Create an event so members know when you&#39;re meeting and can RSVP.</p>
            {club.currentUserRole === "officer" && (
              <ScrollToInputButton
                inputSelector='input[id="event_title"]'
                className="btn-secondary mt-3"
              >
                Create First Event
              </ScrollToInputButton>
            )}
          </div>
        ) : (
          <div className="list-stack mt-4">
            {club.events.map((event) => {
              // Check if event is coming soon (within 48 hours)
              const now = new Date();
              const timeDiff = event.eventDateRaw.getTime() - now.getTime();
              const hoursDiff = timeDiff / (1000 * 60 * 60);
              const isComingSoon = hoursDiff > 0 && hoursDiff <= 48;
              const totalResponses = event.rsvpCounts.yes + event.rsvpCounts.no + event.rsvpCounts.maybe;
              const responsePercent = club.members.length > 0
                ? Math.min(100, Math.round((totalResponses / club.members.length) * 100))
                : 0;
              const attendancePercent = club.members.length > 0
                ? Math.min(100, Math.round((event.rsvpCounts.yes / club.members.length) * 100))
                : 0;

              return (
                <article key={event.id} className="surface-subcard p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="max-w-2xl">
                      <div className="flex items-center gap-2">
                        <h3 className="text-base font-semibold text-slate-900">{event.title}</h3>
                        {isComingSoon && (
                          <span className="inline-flex items-center rounded-full bg-orange-100 px-2 py-0.5 text-xs font-medium text-orange-800">
                            Coming Soon
                          </span>
                        )}
                      </div>
                      <p className="mt-2 text-sm leading-6 text-slate-600">{event.description}</p>
                    </div>
                    <span className={event.userRsvpStatus ? "badge-strong" : "badge-soft"}>
                      {event.userRsvpStatus ? `RSVP ${event.userRsvpStatus}` : "No RSVP"}
                    </span>
                  </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <div className="stat-card p-4">
                    <p className="stat-label">Date</p>
                    <p className="mt-2 text-sm font-semibold text-slate-900">{event.eventDate}</p>
                  </div>
                  <div className="stat-card p-4">
                    <p className="stat-label">Location</p>
                    <p className="mt-2 text-sm font-semibold text-slate-900">{event.location}</p>
                  </div>
                  <div className="stat-card p-4">
                    <p className="stat-label">Going</p>
                    <p className="mt-2 text-sm font-semibold text-slate-900">{event.rsvpCounts.yes} people going</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {attendancePercent}% of the club right now
                    </p>
                  </div>
                  <div className="stat-card p-4">
                    <p className="stat-label">Engagement</p>
                    <p className="mt-2 text-sm font-semibold text-slate-900">
                      {event.rsvpCounts.yes + event.rsvpCounts.maybe >= 5
                        ? "Strong"
                        : event.rsvpCounts.yes + event.rsvpCounts.maybe >= 2
                          ? "Building"
                          : "Early"}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Based on RSVP response volume
                    </p>
                  </div>
                  <div className="stat-card p-4">
                    <p className="stat-label">Attendance</p>
                    <p className="mt-2 text-sm font-semibold text-slate-900">{event.attendanceCount} present</p>
                    <p className="mt-1 text-xs text-slate-500">Checked in during the meeting</p>
                  </div>
                </div>
                <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/80 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-slate-900">Participation</p>
                      <p className="mt-1 text-sm text-slate-600">
                        {totalResponses} of {club.members.length} members responded
                      </p>
                    </div>
                    <span className="badge-soft">
                      {event.rsvpCounts.yes} yes · {event.rsvpCounts.maybe} maybe · {event.rsvpCounts.no} no
                    </span>
                  </div>
                  <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200">
                    <div className="h-full rounded-full bg-slate-900 transition-all" style={{ width: `${responsePercent}%` }} />
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(["yes", "maybe", "no"] as const).map((status) => (
                    <form key={status} action={upsertRsvpAction}>
                      <input type="hidden" name="club_id" value={club.id} />
                      <input type="hidden" name="event_id" value={event.id} />
                      <input type="hidden" name="status" value={status} />
                      <button
                        type="submit"
                        className={`rounded-md px-3 py-1.5 text-xs font-semibold transition ${
                          event.userRsvpStatus === status
                            ? "bg-slate-900 text-white"
                            : "border border-slate-300 bg-white text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        {status.toUpperCase()}
                      </button>
                    </form>
                  ))}
                </div>
                {club.currentUserRole === "officer" ? (
                  <AttendanceChecklist
                    clubId={club.id}
                    eventId={event.id}
                    members={club.members}
                    presentMemberIds={event.presentMemberIds}
                  />
                ) : null}
              </article>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
