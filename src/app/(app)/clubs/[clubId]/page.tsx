import { notFound } from "next/navigation";
import {
  createAnnouncementAction,
  createEventAction,
  removeMemberAction,
  updateMemberRoleAction,
  upsertRsvpAction,
} from "@/app/(app)/clubs/actions";
import { GettingStartedChecklist } from "@/components/ui/getting-started-checklist";
import { ClubSummary } from "@/components/ui/club-summary";
import { CopyJoinCodeButton } from "@/components/ui/copy-join-code-button";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
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
  }>;
};

export default async function ClubPage({ params, searchParams }: ClubPageProps) {
  const { clubId } = await params;
  const query = await searchParams;
  const club = await getClubDetailForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  return (
    <section className="space-y-8">
      <header className="card-surface p-7">
        <p className="section-kicker">Club Profile</p>
        <h1 className="section-title mt-2">{club.name}</h1>
        <p className="section-subtitle max-w-3xl">{club.description}</p>
        <div className="mt-6 grid gap-3 md:grid-cols-3">
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
          <div className="stat-card">
            <p className="stat-label">Officer Join Code</p>
            <p className="stat-value text-[1.2rem]">{club.currentUserRole === "officer" ? club.joinCode : "Hidden"}</p>
            <p className="stat-copy">
              {club.currentUserRole === "officer" ? "Share this with new members." : "Only officers can see the join code."}
            </p>
          </div>
        </div>
      </header>

      <ClubSummary club={club} />

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
            {club.announcements.map((announcement) => (
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
            {club.events.map((event) => (
              <article key={event.id} className="surface-subcard p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="max-w-2xl">
                    <h3 className="text-base font-semibold text-slate-900">{event.title}</h3>
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
                    <p className="stat-label">Responses</p>
                    <p className="mt-2 text-sm font-semibold text-slate-900">
                      Yes {event.rsvpCounts.yes} · No {event.rsvpCounts.no} · Maybe {event.rsvpCounts.maybe}
                    </p>
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
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
