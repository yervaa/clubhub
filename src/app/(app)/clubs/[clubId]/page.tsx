import { notFound } from "next/navigation";
import { createAnnouncementAction, createEventAction, upsertRsvpAction } from "@/app/(app)/clubs/actions";
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
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Club Profile</p>
        <h1 className="section-title mt-2">{club.name}</h1>
        <p className="section-subtitle">{club.description}</p>
        <div className="mt-5 flex flex-wrap gap-2 text-xs font-medium uppercase tracking-[0.08em] text-slate-500">
          <span className="rounded-full bg-slate-100 px-2.5 py-1">Role: {club.currentUserRole}</span>
          <span className="rounded-full bg-slate-100 px-2.5 py-1">{club.members.length} members</span>
          {club.currentUserRole === "officer" ? <span className="rounded-full bg-slate-100 px-2.5 py-1">Join code: {club.joinCode}</span> : null}
        </div>
      </header>

      <div className="card-surface p-6">
        <h2 className="text-lg font-semibold tracking-tight text-slate-900">Members</h2>
        {club.members.length === 0 ? (
          <p className="mt-3 text-sm text-slate-600">No members yet.</p>
        ) : (
          <ul className="mt-4 space-y-2">
            {club.members.map((member) => (
              <li key={member.userId} className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2.5">
                <span className="text-sm text-slate-700">{member.userId}</span>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700">{member.role}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card-surface p-6">
        <h2 className="text-lg font-semibold tracking-tight text-slate-900">Announcements</h2>
        {query.annSuccess ? <p className="alert-success mt-4">{query.annSuccess}</p> : null}
        {query.annError ? <p className="alert-error mt-3">{query.annError}</p> : null}

        {club.currentUserRole === "officer" ? (
          <form action={createAnnouncementAction} className="mt-4 space-y-3 rounded-lg border border-slate-200 bg-slate-50/60 p-4">
            <input type="hidden" name="club_id" value={club.id} />
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
          <p className="mt-4 text-sm text-slate-600">No announcements yet.</p>
        ) : (
          <div className="mt-4 space-y-3">
            {club.announcements.map((announcement) => (
              <article key={announcement.id} className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="text-sm font-semibold text-slate-900">{announcement.title}</h3>
                <p className="mt-1 text-sm text-slate-600">{announcement.content}</p>
                <p className="mt-2 text-xs text-slate-500">{announcement.createdAt}</p>
              </article>
            ))}
          </div>
        )}
      </div>

      <div className="card-surface p-6">
        <h2 className="text-lg font-semibold tracking-tight text-slate-900">Events</h2>
        {query.eventSuccess ? <p className="alert-success mt-4">{query.eventSuccess}</p> : null}
        {query.eventError ? <p className="alert-error mt-3">{query.eventError}</p> : null}
        {query.rsvpSuccess ? <p className="alert-success mt-3">{query.rsvpSuccess}</p> : null}
        {query.rsvpError ? <p className="alert-error mt-3">{query.rsvpError}</p> : null}

        {club.currentUserRole === "officer" ? (
          <form action={createEventAction} className="mt-4 space-y-3 rounded-lg border border-slate-200 bg-slate-50/60 p-4">
            <input type="hidden" name="club_id" value={club.id} />
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
          <p className="mt-4 text-sm text-slate-600">No events yet.</p>
        ) : (
          <div className="mt-4 space-y-3">
            {club.events.map((event) => (
              <article key={event.id} className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="text-sm font-semibold text-slate-900">{event.title}</h3>
                <p className="mt-1 text-sm text-slate-600">{event.description}</p>
                <p className="mt-2 text-sm text-slate-600">{event.location}</p>
                <p className="mt-1 text-xs text-slate-500">{event.eventDate}</p>
                <p className="mt-2 text-xs font-medium uppercase tracking-[0.08em] text-slate-500">
                  Your RSVP: {event.userRsvpStatus ?? "not set"}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Yes: {event.rsvpCounts.yes} · No: {event.rsvpCounts.no} · Maybe: {event.rsvpCounts.maybe}
                </p>
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
