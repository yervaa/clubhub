import {
  approveAnnouncementAdvisorAction,
  approveEventAdvisorAction,
  rejectAnnouncementAdvisorAction,
  rejectEventAdvisorAction,
} from "@/app/(app)/clubs/advisor-actions";
import { CardSection } from "@/components/ui/page-patterns";
import { PageIntro } from "@/components/ui/page-intro";

type PendingEventRow = {
  id: string;
  title: string;
  event_date: string;
  location: string | null;
  series_id: string | null;
  series_occurrence: number | null;
};

type PendingAnnouncementRow = {
  id: string;
  title: string;
  created_at: string;
  scheduled_for: string | null;
};

export type AdvisorDashboardProps = {
  clubId: string;
  clubName: string;
  requireEventApproval: boolean;
  requireAnnouncementApproval: boolean;
  canEvents: boolean;
  canAnnouncements: boolean;
  pendingEvents: PendingEventRow[];
  pendingAnnouncements: PendingAnnouncementRow[];
  query: { success?: string; error?: string };
};

export function AdvisorDashboard({
  clubId,
  clubName,
  requireEventApproval,
  requireAnnouncementApproval,
  canEvents,
  canAnnouncements,
  pendingEvents,
  pendingAnnouncements,
  query,
}: AdvisorDashboardProps) {
  const eventCount = pendingEvents.length;
  const annCount = pendingAnnouncements.length;

  return (
    <section className="space-y-5">
      <PageIntro
        kicker="Advisor"
        title="Review submissions"
        description={`Pending items for ${clubName}. Approve to make them visible to members, or reject with a short note for organizers.`}
      />

      {query.success ? (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-900">
          {decodeURIComponent(query.success.replace(/\+/g, " "))}
        </div>
      ) : null}
      {query.error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-900">
          {decodeURIComponent(query.error.replace(/\+/g, " "))}
        </div>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Pending events</p>
          <p className="mt-1 text-2xl font-bold text-slate-900">{eventCount}</p>
          {!requireEventApproval && canEvents ? (
            <p className="mt-2 text-xs text-slate-600">Event approval is off in club settings — new events publish without review.</p>
          ) : null}
        </div>
        <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Pending announcements</p>
          <p className="mt-1 text-2xl font-bold text-slate-900">{annCount}</p>
          {!requireAnnouncementApproval && canAnnouncements ? (
            <p className="mt-2 text-xs text-slate-600">Announcement approval is off — posts go live without review.</p>
          ) : null}
        </div>
      </div>

      {canEvents ? (
        <CardSection className="border border-slate-200/90">
          <h2 className="text-lg font-semibold text-slate-900">Events</h2>
          {pendingEvents.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No events are waiting for approval.</p>
          ) : (
            <ul className="mt-4 space-y-4">
              {pendingEvents.map((ev) => (
                <li
                  key={ev.id}
                  className="rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-3 sm:flex sm:items-start sm:justify-between sm:gap-4"
                >
                  <div className="min-w-0">
                    <p className="font-semibold text-slate-900">{ev.title}</p>
                    <p className="mt-1 text-sm text-slate-600">
                      {new Date(ev.event_date).toLocaleString(undefined, {
                        month: "short",
                        day: "numeric",
                        hour: "numeric",
                        minute: "2-digit",
                      })}
                      {ev.location?.trim() ? ` · ${ev.location}` : ""}
                    </p>
                    {ev.series_id ? (
                      <p className="mt-1 text-xs font-medium text-indigo-700">
                        Recurring series{ev.series_occurrence ? ` · Occurrence ${ev.series_occurrence}` : ""}
                      </p>
                    ) : null}
                  </div>
                  <div className="mt-3 flex min-w-[min(100%,16rem)] flex-col gap-2 sm:mt-0">
                    <form action={approveEventAdvisorAction}>
                      <input type="hidden" name="club_id" value={clubId} />
                      <input type="hidden" name="event_id" value={ev.id} />
                      <button type="submit" className="btn-primary min-h-10 w-full text-xs">
                        Approve
                      </button>
                    </form>
                    <form action={rejectEventAdvisorAction} className="space-y-2">
                      <input type="hidden" name="club_id" value={clubId} />
                      <input type="hidden" name="event_id" value={ev.id} />
                      <label className="block text-xs font-medium text-slate-700" htmlFor={`reject-ev-${ev.id}`}>
                        Optional note to organizer
                      </label>
                      <textarea
                        id={`reject-ev-${ev.id}`}
                        name="reason"
                        rows={2}
                        maxLength={500}
                        className="input-control w-full resize-y text-sm"
                        placeholder="Why this can’t be published as-is…"
                      />
                      <button type="submit" className="btn-danger min-h-10 w-full text-xs">
                        Not approved
                      </button>
                    </form>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardSection>
      ) : null}

      {canAnnouncements ? (
        <CardSection className="border border-slate-200/90">
          <h2 className="text-lg font-semibold text-slate-900">Announcements</h2>
          {pendingAnnouncements.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No announcements are waiting for approval.</p>
          ) : (
            <ul className="mt-4 space-y-4">
              {pendingAnnouncements.map((a) => (
                <li
                  key={a.id}
                  className="rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-3 sm:flex sm:items-start sm:justify-between sm:gap-4"
                >
                  <div className="min-w-0">
                    <p className="font-semibold text-slate-900">{a.title}</p>
                    <p className="mt-1 text-sm text-slate-600">
                      Submitted {new Date(a.created_at).toLocaleString()}
                      {a.scheduled_for && new Date(a.scheduled_for).getTime() > Date.now()
                        ? ` · Scheduled ${new Date(a.scheduled_for).toLocaleString()}`
                        : ""}
                    </p>
                  </div>
                  <div className="mt-3 flex min-w-[min(100%,16rem)] flex-col gap-2 sm:mt-0">
                    <form action={approveAnnouncementAdvisorAction}>
                      <input type="hidden" name="club_id" value={clubId} />
                      <input type="hidden" name="announcement_id" value={a.id} />
                      <button type="submit" className="btn-primary min-h-10 w-full text-xs">
                        Approve
                      </button>
                    </form>
                    <form action={rejectAnnouncementAdvisorAction} className="space-y-2">
                      <input type="hidden" name="club_id" value={clubId} />
                      <input type="hidden" name="announcement_id" value={a.id} />
                      <label className="block text-xs font-medium text-slate-700" htmlFor={`reject-ann-${a.id}`}>
                        Optional note to organizer
                      </label>
                      <textarea
                        id={`reject-ann-${a.id}`}
                        name="reason"
                        rows={2}
                        maxLength={500}
                        className="input-control w-full resize-y text-sm"
                      />
                      <button type="submit" className="btn-danger min-h-10 w-full text-xs">
                        Not approved
                      </button>
                    </form>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardSection>
      ) : null}
    </section>
  );
}
