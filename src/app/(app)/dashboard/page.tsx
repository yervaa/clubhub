import Link from "next/link";
import {
  ContentSummaryListLink,
  EventSummaryBlock,
  EventSummaryListLink,
  eventSoonBadge,
} from "@/components/ui/event-summary";
import { getDashboardData } from "@/lib/clubs/queries";

function getDashboardAlertLabel(type: Awaited<ReturnType<typeof getDashboardData>>["needsAttentionAlerts"][number]["type"]) {
  switch (type) {
    case "upcoming_event_low_rsvp":
      return "RSVP";
    case "attendance_not_marked":
      return "Attendance";
    case "no_upcoming_events":
      return "Schedule";
    case "no_recent_announcement":
      return "Updates";
    default:
      return "Alert";
  }
}

function taskPriorityClass(priority: string) {
  switch (priority) {
    case "urgent":
      return "bg-rose-100 text-rose-800";
    case "high":
      return "bg-orange-100 text-orange-800";
    case "medium":
      return "bg-amber-100 text-amber-800";
    default:
      return "bg-slate-100 text-slate-600";
  }
}

export default async function DashboardPage() {
  const {
    clubs,
    upcomingEvents,
    recentAnnouncements,
    needsAttentionAlerts,
    myOpenTasks,
    unreadNotificationCount,
  } = await getDashboardData();

  const officerClubIds = new Set(clubs.filter((c) => c.role === "officer").map((c) => c.id));
  const leadershipAlerts = needsAttentionAlerts.filter((a) => officerClubIds.has(a.clubId));
  const officerClubs = officerClubIds.size;

  const now = new Date();
  const sevenDaysFromNow = new Date(now);
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);

  const thisWeekEvents = upcomingEvents.filter((event) => {
    const eventDate = new Date(event.eventDateRaw);
    return eventDate >= now && eventDate <= sevenDaysFromNow;
  });

  const urgentEventCount = thisWeekEvents.filter((event) => {
    const eventDate = new Date(event.eventDateRaw);
    const hoursUntil = (eventDate.getTime() - now.getTime()) / (1000 * 60 * 60);
    return hoursUntil <= 48;
  }).length;

  const nextEvent = upcomingEvents[0] ?? null;
  const hasClubs = clubs.length > 0;

  return (
    <section className="space-y-10">
      {/* Member-first header: no primary “Create club” */}
      <header className="flex flex-col gap-4 border-b border-slate-200/80 pb-8">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 max-w-2xl">
            <p className="section-kicker text-slate-600">Home</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950 md:text-4xl">
              What matters for you right now
            </h1>
            <p className="mt-3 text-base leading-7 text-slate-600">
              Upcoming gatherings, your tasks, and news from the clubs you belong to—without the admin noise up front.
            </p>
          </div>
          <div className="flex flex-shrink-0 flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
            <Link
              href="/notifications"
              className="btn-secondary inline-flex items-center justify-center gap-2 text-center"
            >
              Notifications
              {unreadNotificationCount > 0 ? (
                <span className="rounded-full bg-slate-900 px-2 py-0.5 text-xs font-semibold text-white">
                  {unreadNotificationCount > 99 ? "99+" : unreadNotificationCount}
                </span>
              ) : null}
            </Link>
            <Link href="/clubs/join" className="btn-secondary text-center">
              Join a club
            </Link>
            <Link
              href="/clubs/create"
              className="rounded-lg px-3 py-2.5 text-center text-sm font-medium text-slate-500 transition hover:bg-slate-100 hover:text-slate-800"
            >
              Start a club
            </Link>
          </div>
        </div>
      </header>

      {!hasClubs ? (
        <div className="rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-8">
          <p className="text-lg font-semibold text-slate-900">Join a club to see your schedule and updates</p>
          <p className="mt-2 max-w-lg text-sm leading-6 text-slate-600">
            Most people get started with an invite or join code. If you are starting something new, you can still create a
            club— it is just one step removed so it does not get in the way.
          </p>
          <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
            <Link href="/clubs/join" className="btn-primary flex-1 text-center sm:flex-none sm:px-8">
              Join with a code
            </Link>
            <Link href="/clubs/create" className="text-center text-sm font-medium text-slate-500 hover:text-slate-800 sm:px-4">
              Or start a new club →
            </Link>
          </div>
        </div>
      ) : (
        <>
          {/* 1. Personalized / time-sensitive */}
          <section aria-labelledby="dash-for-you-heading">
            <h2 id="dash-for-you-heading" className="section-title text-xl">
              For you
            </h2>
            <p className="section-subtitle mt-1 max-w-2xl">
              Next on your calendar, open tasks, and anything time-sensitive.
            </p>

            <div className="mt-6 grid gap-4 lg:grid-cols-12 lg:gap-6">
              <div className="space-y-4 lg:col-span-7">
                <div className="card-surface p-5 sm:p-6">
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-4">
                    <p className="section-kicker">Next up</p>
                    {nextEvent ? (
                      <span className={urgentEventCount > 0 ? "badge-strong" : "badge-soft"}>
                        {urgentEventCount > 0 ? `${urgentEventCount} starting soon` : "Scheduled"}
                      </span>
                    ) : null}
                  </div>
                  {nextEvent ? (
                    <>
                      <div className="pt-4">
                        <EventSummaryBlock
                          title={nextEvent.title}
                          titleAs="h3"
                          titleSize="hero"
                          secondaryLine={`${nextEvent.clubName} · ${nextEvent.eventType}`}
                          at={nextEvent.eventDateRaw}
                          location={nextEvent.location}
                          supportingBorder={false}
                        />
                      </div>
                      <div className="mt-5 flex flex-wrap gap-2 border-t border-slate-100 pt-4">
                        <Link href={`/clubs/${nextEvent.clubId}/events`} className="btn-primary text-sm">
                          View in club
                        </Link>
                        <Link href={`/clubs/${nextEvent.clubId}`} className="btn-secondary text-sm">
                          Club home
                        </Link>
                      </div>
                    </>
                  ) : (
                    <p className="pt-4 text-sm leading-relaxed text-slate-600">
                      When your clubs add meetings or events, they will show up here first.
                    </p>
                  )}
                </div>

                {upcomingEvents.length > 0 ? (
                  <div className="overflow-hidden rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)]">
                    <div className="flex items-start justify-between gap-3 border-b border-slate-100 bg-slate-50/50 px-4 py-3 sm:px-5 sm:py-3.5">
                      <div>
                        <p className="section-kicker">Coming up</p>
                        <p className="mt-0.5 text-base font-semibold text-slate-900">More events</p>
                      </div>
                      <span className="badge-soft shrink-0">{upcomingEvents.length}</span>
                    </div>
                    <ul>
                      {upcomingEvents.slice(0, 5).map((event) => {
                        const hoursUntil = (new Date(event.eventDateRaw).getTime() - now.getTime()) / (1000 * 60 * 60);
                        const soon = eventSoonBadge(hoursUntil);
                        return (
                          <li key={event.id} className="border-b border-slate-100 last:border-b-0">
                            <EventSummaryListLink
                              href={`/clubs/${event.clubId}/events`}
                              title={event.title}
                              clubName={event.clubName}
                              eventType={event.eventType}
                              at={event.eventDateRaw}
                              location={event.location}
                              titleAside={soon}
                            />
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ) : null}
              </div>

              <div className="space-y-4 lg:col-span-5">
                <div className="card-surface p-5">
                  <div className="flex items-center justify-between gap-2">
                    <p className="section-kicker">My tasks</p>
                    {myOpenTasks.length > 0 ? <span className="badge-soft">{myOpenTasks.length} open</span> : null}
                  </div>
                  {myOpenTasks.length === 0 ? (
                    <p className="mt-3 text-sm leading-6 text-slate-600">
                      No open tasks assigned to you. When officers assign work, it will land here.
                    </p>
                  ) : (
                    <ul className="mt-4 space-y-2">
                      {myOpenTasks.map((task) => (
                        <li key={task.id}>
                          <Link
                            href={`/clubs/${task.clubId}/tasks`}
                            className="block rounded-xl border border-slate-100 bg-slate-50/50 p-3 transition hover:border-slate-200 hover:bg-slate-50"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <p className="text-sm font-semibold text-slate-900">{task.title}</p>
                              <span className={`flex-shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${taskPriorityClass(task.priority)}`}>
                                {task.priority}
                              </span>
                            </div>
                            <p className="mt-1 text-xs text-slate-500">{task.clubName}</p>
                            <p className="mt-1 text-xs text-slate-600">
                              {task.isOverdue ? (
                                <span className="font-semibold text-rose-700">Overdue</span>
                              ) : task.dueAt ? (
                                <>Due {task.dueAt}</>
                              ) : (
                                <>No due date</>
                              )}
                            </p>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-5">
                  <p className="section-kicker">Stay in the loop</p>
                  <p className="mt-2 text-sm leading-6 text-slate-600">
                    {unreadNotificationCount > 0
                      ? `You have ${unreadNotificationCount} unread notification${unreadNotificationCount === 1 ? "" : "s"}.`
                      : "You are caught up on notifications."}
                  </p>
                  <Link href="/notifications" className="action-link mt-3 inline-block">
                    Open inbox →
                  </Link>
                </div>
              </div>
            </div>
          </section>

          {/* 2. What’s new */}
          {recentAnnouncements.length > 0 ? (
            <section aria-labelledby="dash-whats-new-heading">
              <h2 id="dash-whats-new-heading" className="section-title text-xl">
                Latest updates
              </h2>
              <p className="section-subtitle mt-1">Recent announcements from your clubs.</p>
              <ul className="mt-5 overflow-hidden rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)]">
                {recentAnnouncements.slice(0, 6).map((announcement, index) => (
                  <li key={announcement.id} className="border-b border-slate-100 last:border-b-0">
                    <ContentSummaryListLink
                      href={`/clubs/${announcement.clubId}/announcements`}
                      title={announcement.title}
                      secondaryLine={announcement.clubName}
                      timestamp={announcement.createdAtRaw}
                      titleAside={
                        index === 0 ? (
                          <span className="rounded-md bg-blue-100 px-2 py-0.5 text-[11px] font-semibold text-blue-900 ring-1 ring-blue-200/80">
                            New
                          </span>
                        ) : null
                      }
                    />
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {/* 3. My clubs */}
          <section aria-labelledby="dash-clubs-heading">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 id="dash-clubs-heading" className="section-title text-xl">
                  My clubs
                </h2>
                <p className="section-subtitle mt-1 max-w-xl">
                  Jump into a workspace. Your role is shown for context—it is not the main event.
                </p>
              </div>
              <Link href="/clubs/join" className="text-sm font-medium text-slate-600 hover:text-slate-900">
                Join another club →
              </Link>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {clubs.map((club) => (
                <article
                  key={club.id}
                  className={`dashboard-club-card rounded-xl border border-slate-200 bg-white ${club.role === "officer" ? "is-officer" : ""}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="text-lg font-semibold tracking-tight text-slate-900">{club.name}</h3>
                      <p className="mt-1 text-xs text-slate-500">
                        {club.role === "officer" ? "Officer · can manage events and posts" : "Member"}
                      </p>
                    </div>
                  </div>
                  <p className="mt-3 min-h-14 text-sm leading-6 text-slate-600">{club.description}</p>
                  {club.role === "officer" ? (
                    <p className="mt-3 text-xs text-slate-500">
                      Join code{" "}
                      <span className="font-mono font-semibold tracking-wider text-slate-700">{club.joinCode}</span>
                    </p>
                  ) : null}
                  <Link href={`/clubs/${club.id}`} className="action-link mt-4 inline-block">
                    Open workspace →
                  </Link>
                </article>
              ))}
            </div>
            <p className="mt-6 text-center text-sm text-slate-500">
              Want to launch something new?{" "}
              <Link href="/clubs/create" className="font-medium text-slate-700 underline decoration-slate-300 underline-offset-2 hover:text-slate-900">
                Start a club
              </Link>
            </p>
          </section>

          {/* 4. Leadership & club health (officers only) */}
          {officerClubs > 0 ? (
            <section className="card-surface p-6" aria-labelledby="dash-leadership-heading">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Leadership</p>
                  <h2 id="dash-leadership-heading" className="mt-2 text-lg font-semibold tracking-tight text-slate-900">
                    Tools and follow-ups for clubs you help run
                  </h2>
                  <p className="mt-1 text-sm text-slate-600">
                    Scheduling, attendance, and announcements—only shown here because you are an officer in at least one club.
                  </p>
                </div>
                <span className="badge-soft">{leadershipAlerts.length} items</span>
              </div>

              {leadershipAlerts.length === 0 ? (
                <div className="mt-4 rounded-xl border border-emerald-200/80 bg-emerald-50/50 p-5">
                  <p className="font-semibold text-slate-900">Nothing urgent on the leadership side.</p>
                  <p className="mt-1 text-sm text-slate-600">Check back after events or when you add new meetings.</p>
                </div>
              ) : (
                <div className="list-stack mt-4">
                  {leadershipAlerts.map((alert) => (
                    <article key={alert.id} className="surface-subcard p-4">
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div className="max-w-2xl">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="badge-soft">{alert.clubName}</span>
                            <span className="badge-soft">{getDashboardAlertLabel(alert.type)}</span>
                            <h3 className="text-sm font-semibold text-slate-900">{alert.title}</h3>
                          </div>
                          <p className="mt-2 text-sm leading-6 text-slate-600">{alert.description}</p>
                        </div>
                        <Link href={alert.ctaHref} className="btn-secondary whitespace-nowrap">
                          {alert.ctaLabel}
                        </Link>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </section>
          ) : null}
        </>
      )}
    </section>
  );
}
