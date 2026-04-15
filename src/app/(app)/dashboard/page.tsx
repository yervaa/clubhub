import Link from "next/link";
import {
  ContentSummaryListLink,
  EventSummaryBlock,
  EventSummaryListLink,
  eventSoonBadge,
} from "@/components/ui/event-summary";
import { PageIntro } from "@/components/ui/page-intro";
import { ClubJoinCodeRow } from "@/components/ui/club-join-code-row";
import { DashboardPersistedDetails } from "@/components/ui/dashboard-persisted-details";
import { ActivityFeed } from "@/components/ui/activity-feed";
import { getDashboardData, type DashboardTaskPreview } from "@/lib/clubs/queries";
import { getGlobalActivityFeed } from "@/lib/activity/queries";

const LS_MORE_EVENTS = "clubhub:dash:more-events";
const LS_MORE_ANNOUNCEMENTS = "clubhub:dash:more-announcements";
const TASKS_VISIBLE = 4;

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

function getTaskDueStatus(task: DashboardTaskPreview, now: Date): "overdue" | "today" | "upcoming" | "none" {
  if (task.isOverdue) return "overdue";
  if (!task.dueAtIso) return "none";
  const d = new Date(task.dueAtIso);
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  const end = new Date(now);
  end.setHours(23, 59, 59, 999);
  if (d >= start && d <= end) return "today";
  return "upcoming";
}

function sortTasksForDashboard(tasks: DashboardTaskPreview[], now: Date): DashboardTaskPreview[] {
  const rank = (t: DashboardTaskPreview) => {
    const s = getTaskDueStatus(t, now);
    if (s === "overdue") return 0;
    if (s === "today") return 1;
    if (s === "upcoming") return 2;
    return 3;
  };
  return [...tasks].sort((a, b) => {
    const d = rank(a) - rank(b);
    if (d !== 0) return d;
    if (a.dueAtIso && b.dueAtIso) return new Date(a.dueAtIso).getTime() - new Date(b.dueAtIso).getTime();
    if (a.dueAtIso) return -1;
    if (b.dueAtIso) return 1;
    return 0;
  });
}

function taskDueChipClass(status: ReturnType<typeof getTaskDueStatus>) {
  switch (status) {
    case "overdue":
      return "bg-rose-100 text-rose-800 ring-rose-200/80";
    case "today":
      return "bg-amber-100 text-amber-900 ring-amber-200/80";
    case "upcoming":
      return "bg-slate-100 text-slate-700 ring-slate-200/80";
    default:
      return "bg-slate-50 text-slate-500 ring-slate-200/60";
  }
}

function taskDueChipLabel(status: ReturnType<typeof getTaskDueStatus>) {
  switch (status) {
    case "overdue":
      return "Overdue";
    case "today":
      return "Due today";
    case "upcoming":
      return "Upcoming";
    default:
      return "No date";
  }
}

function detailsShellClassName(extra = "") {
  return `dashboard-disclosure group rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)] ${extra}`.trim();
}

function DisclosureChevron() {
  return (
    <svg className="dashboard-disclosure-chevron h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden>
      <path
        fillRule="evenodd"
        d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function NotificationsBellIcon({ className }: { className?: string }) {
  return (
    <svg className={className} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" aria-hidden>
      <path
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
      />
    </svg>
  );
}

export default async function DashboardPage() {
  const [
    {
      clubs,
      upcomingEvents,
      recentAnnouncements,
      needsAttentionAlerts,
      myOpenTasks,
      unreadNotificationCount,
    },
    activityItems,
  ] = await Promise.all([getDashboardData(), getGlobalActivityFeed(12)]);

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

  const hoursUntilNext =
    nextEvent !== null ? (new Date(nextEvent.eventDateRaw).getTime() - now.getTime()) / (1000 * 60 * 60) : null;
  const nextEventWithin24h = nextEvent !== null && hoursUntilNext !== null && hoursUntilNext > 0 && hoursUntilNext <= 24;
  const nextEventLater = nextEvent !== null && hoursUntilNext !== null && hoursUntilNext > 24;

  const furtherEvents = nextEvent ? upcomingEvents.filter((e) => e.id !== nextEvent.id).slice(0, 8) : upcomingEvents.slice(0, 8);

  const sortedTasks = sortTasksForDashboard(myOpenTasks, now);
  const tasksShown = sortedTasks.slice(0, TASKS_VISIBLE);
  const tasksOverflow = sortedTasks.length > TASKS_VISIBLE;
  const viewAllTasksHref = sortedTasks[0] ? `/clubs/${sortedTasks[0].clubId}/tasks` : "/clubs";

  const importantAnnouncements = recentAnnouncements.slice(0, 2);
  const feedAfterImportant = recentAnnouncements.slice(2);
  const announcementPrimary = feedAfterImportant.slice(0, 3);
  const announcementMore = feedAfterImportant.slice(3, 8);

  return (
    <section className="space-y-6 lg:space-y-8">
      <PageIntro
        title="Dashboard"
        description="What is next on your calendar, open tasks, and updates from your clubs without extra noise up front."
        actions={
          <>
            <Link
              href="/notifications"
              className="btn-secondary inline-flex min-h-11 items-center justify-center gap-2 text-center text-sm sm:min-h-0"
            >
              Inbox
              {unreadNotificationCount > 0 ? (
                <span className="rounded-full bg-slate-900 px-2 py-0.5 text-xs font-semibold text-white tabular-nums">
                  {unreadNotificationCount > 99 ? "99+" : unreadNotificationCount}
                </span>
              ) : null}
            </Link>
            <Link href="/clubs/join" className="btn-secondary min-h-11 text-center text-sm sm:min-h-0">
              Join club
            </Link>
            <Link
              href="/clubs/create"
              className="inline-flex min-h-11 items-center justify-center rounded-lg px-3 py-2 text-center text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 sm:min-h-0"
            >
              Start a club
            </Link>
          </>
        }
      />

      {!hasClubs ? (
        <div className="rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-6 sm:p-8">
          <p className="text-lg font-semibold text-slate-900">Join a club to see your schedule and updates</p>
          <p className="mt-2 max-w-lg text-sm leading-6 text-slate-600">
            Most people start with an invite or join code. Starting something new is one step away when you need it.
          </p>
          <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
            <Link href="/clubs/join" className="btn-primary flex-1 text-center sm:flex-none sm:px-8">
              Join with a code
            </Link>
            <Link href="/clubs/create" className="text-center text-sm font-medium text-slate-500 hover:text-slate-800 sm:px-4">
              Or start a new club →
            </Link>
            <Link href="/discover" className="text-center text-sm font-medium text-slate-500 hover:text-slate-800 sm:px-4">
              Browse clubs first →
            </Link>
          </div>
        </div>
      ) : (
        <>
          <ActivityFeed
            items={activityItems.slice(0, 8)}
            title="Recent activity"
            description="Live updates from announcements, events, RSVPs, attendance, and role changes."
            viewMoreHref="/activity"
            variant="primary"
            emptyHint="This feed comes alive when your clubs post announcements, schedule events, and log participation."
            emptyAction={
              <Link href="/clubs/join" className="btn-primary">
                Join your first club
              </Link>
            }
          />

          <section id="important-now" aria-labelledby="dash-priority-heading" className="space-y-4">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 id="dash-priority-heading" className="text-lg font-semibold tracking-tight text-slate-900 sm:text-xl">
                  Important now
                </h2>
                <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">
                  Tasks, soonest deadlines, then what&apos;s next on your calendar and in your inbox.
                </p>
              </div>
              {sortedTasks.length > 0 ? (
                <span className="text-xs font-medium text-slate-500 tabular-nums sm:text-sm">
                  {sortedTasks.length} open task{sortedTasks.length === 1 ? "" : "s"}
                </span>
              ) : null}
            </div>

            <div className="flex flex-col gap-4">
              {/* 1 — Tasks (overdue first) */}
              <div className="card-surface p-4 sm:p-5">
                <div className="flex items-center justify-between gap-2">
                  <p className="section-kicker">My tasks</p>
                  {sortedTasks.length > 0 ? (
                    <span className="badge-soft tabular-nums">{sortedTasks.length} open</span>
                  ) : null}
                </div>
                {sortedTasks.length === 0 ? (
                  <p className="mt-3 text-sm leading-relaxed text-slate-600">
                    No open tasks assigned to you. When officers assign work, it&apos;ll appear here.
                  </p>
                ) : (
                  <>
                    <ul className="mt-3 space-y-2">
                      {tasksShown.map((task) => {
                        const dueStatus = getTaskDueStatus(task, now);
                        return (
                          <li key={task.id}>
                            <Link
                              href={`/clubs/${task.clubId}/tasks`}
                              className="block rounded-xl border border-slate-100 bg-slate-50/50 p-3 transition hover:border-slate-200 hover:bg-slate-50"
                            >
                              <div className="flex flex-wrap items-start justify-between gap-2">
                                <p className="min-w-0 flex-1 text-sm font-semibold text-slate-900">{task.title}</p>
                                <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
                                  <span
                                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${taskDueChipClass(dueStatus)}`}
                                  >
                                    {taskDueChipLabel(dueStatus)}
                                  </span>
                                  <span
                                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${taskPriorityClass(task.priority)}`}
                                  >
                                    {task.priority}
                                  </span>
                                </div>
                              </div>
                              <p className="mt-1 text-xs text-slate-500">{task.clubName}</p>
                              {task.dueAt && !task.isOverdue && dueStatus !== "today" ? (
                                <p className="mt-0.5 text-xs text-slate-600">Due {task.dueAt}</p>
                              ) : null}
                            </Link>
                          </li>
                        );
                      })}
                    </ul>
                    {tasksOverflow ? (
                      <Link
                        href={viewAllTasksHref}
                        className="action-link mt-3 inline-block text-sm font-semibold text-slate-800"
                      >
                        View all tasks →
                      </Link>
                    ) : null}
                  </>
                )}
              </div>

              {/* 2 — Next event &lt; 24h */}
              {nextEventWithin24h && nextEvent ? (
                <div className="card-surface p-4 sm:p-6">
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-3 sm:pb-4">
                    <p className="section-kicker">Starting soon</p>
                    <span className="badge-strong">Within 24h</span>
                  </div>
                  <div className="pt-4">
                    <EventSummaryBlock
                      title={nextEvent.title}
                      titleAs="h3"
                      titleSize="panel"
                      secondaryLine={`${nextEvent.clubName} · ${nextEvent.eventType}`}
                      at={nextEvent.eventDateRaw}
                      location={nextEvent.location}
                      supportingBorder={false}
                    />
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-100 pt-4">
                    <Link href={`/clubs/${nextEvent.clubId}/events`} className="btn-primary text-sm">
                      View in club
                    </Link>
                    <Link href={`/clubs/${nextEvent.clubId}`} className="btn-secondary text-sm">
                      Club home
                    </Link>
                  </div>
                </div>
              ) : null}

              {/* 3 — Notifications */}
              <Link
                href="/notifications"
                className="flex items-center gap-3 rounded-xl border border-slate-200 bg-gradient-to-r from-slate-50 to-white p-3.5 shadow-sm transition hover:border-slate-300 hover:shadow-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 sm:p-4"
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-900 text-white">
                  <NotificationsBellIcon className="h-5 w-5" />
                </span>
                <span className="min-w-0 flex-1 text-left">
                  <span className="block text-sm font-semibold text-slate-900">
                    Notifications
                    {unreadNotificationCount > 0 ? (
                      <>
                        {" "}
                        ·{" "}
                        <span className="tabular-nums text-blue-700">
                          {unreadNotificationCount > 99 ? "99+" : unreadNotificationCount} new
                        </span>
                      </>
                    ) : null}
                  </span>
                  <span className="mt-0.5 block text-xs text-slate-500">
                    {unreadNotificationCount > 0 ? "Open your inbox →" : "You are all caught up →"}
                  </span>
                </span>
                <span className="shrink-0 text-slate-400" aria-hidden>
                  →
                </span>
              </Link>

              {/* 4 — Announcements peek */}
              {importantAnnouncements.length > 0 ? (
                <div className="card-surface p-4 sm:p-5">
                  <div className="flex flex-wrap items-end justify-between gap-2">
                    <p className="section-kicker">Latest from clubs</p>
                    {feedAfterImportant.length > 0 ? (
                      <Link href="#latest-updates" className="text-xs font-semibold text-slate-600 hover:text-slate-900">
                        More updates →
                      </Link>
                    ) : null}
                  </div>
                  <ul className="mt-3 divide-y divide-slate-100 rounded-lg border border-slate-100">
                    {importantAnnouncements.map((announcement, index) => (
                      <li key={announcement.id} className="first:rounded-t-lg last:rounded-b-lg">
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
                </div>
              ) : null}

              {/* 5 — Next event &gt; 24h (or only card when not within 24h) */}
              {nextEventLater && nextEvent ? (
                <div className="card-surface p-4 sm:p-6">
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-3 sm:pb-4">
                    <p className="section-kicker">Next up</p>
                    {urgentEventCount > 0 ? (
                      <span className="badge-strong">{urgentEventCount} soon</span>
                    ) : (
                      <span className="badge-soft">Scheduled</span>
                    )}
                  </div>
                  <div className="pt-4">
                    <EventSummaryBlock
                      title={nextEvent.title}
                      titleAs="h3"
                      titleSize="panel"
                      secondaryLine={`${nextEvent.clubName} · ${nextEvent.eventType}`}
                      at={nextEvent.eventDateRaw}
                      location={nextEvent.location}
                      supportingBorder={false}
                    />
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-100 pt-4">
                    <Link href={`/clubs/${nextEvent.clubId}/events`} className="btn-primary text-sm">
                      View in club
                    </Link>
                    <Link href={`/clubs/${nextEvent.clubId}`} className="btn-secondary text-sm">
                      Club home
                    </Link>
                  </div>
                </div>
              ) : null}

              {!nextEventWithin24h && !nextEventLater && !nextEvent ? (
                <div className="card-surface p-4 sm:p-6">
                  <p className="section-kicker">Next up</p>
                  <p className="mt-3 text-sm leading-relaxed text-slate-600">
                    When your clubs add meetings or events, they&apos;ll show up here.
                  </p>
                </div>
              ) : null}

              {/* 6 — More events (persisted) */}
              {furtherEvents.length > 0 ? (
                <DashboardPersistedDetails
                  storageKey={LS_MORE_EVENTS}
                  className={detailsShellClassName()}
                  summary={
                    <summary className="dashboard-disclosure-summary px-4 py-3.5 sm:px-5">
                      <div className="min-w-0 flex-1">
                        <p className="section-kicker">Calendar</p>
                        <p className="mt-0.5 text-sm font-semibold text-slate-900">More upcoming events</p>
                      </div>
                      <span className="flex shrink-0 items-center gap-2">
                        <span className="badge-soft tabular-nums">{furtherEvents.length}</span>
                        <DisclosureChevron />
                      </span>
                    </summary>
                  }
                >
                  <ul className="border-t border-slate-100">
                    {furtherEvents.map((event) => {
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
                </DashboardPersistedDetails>
              ) : null}
            </div>
          </section>

          {feedAfterImportant.length > 0 ? (
            <section id="latest-updates" aria-labelledby="dash-feed-heading" className="space-y-3">
              <div>
                <h2 id="dash-feed-heading" className="text-lg font-semibold tracking-tight text-slate-900 sm:text-xl">
                  Latest updates
                </h2>
                <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">More announcements from your clubs.</p>
              </div>
              {announcementPrimary.length > 0 ? (
                <ul className="overflow-hidden rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)]">
                  {announcementPrimary.map((announcement) => (
                    <li key={announcement.id} className="border-b border-slate-100 last:border-b-0">
                      <ContentSummaryListLink
                        href={`/clubs/${announcement.clubId}/announcements`}
                        title={announcement.title}
                        secondaryLine={announcement.clubName}
                        timestamp={announcement.createdAtRaw}
                      />
                    </li>
                  ))}
                </ul>
              ) : null}
              {announcementMore.length > 0 ? (
                <DashboardPersistedDetails
                  storageKey={LS_MORE_ANNOUNCEMENTS}
                  className={detailsShellClassName()}
                  summary={
                    <summary className="dashboard-disclosure-summary px-4 py-3 sm:px-5">
                      <span className="min-w-0 flex-1 text-sm font-semibold text-slate-800">More announcements</span>
                      <span className="flex shrink-0 items-center gap-2">
                        <span className="badge-soft tabular-nums">{announcementMore.length}</span>
                        <DisclosureChevron />
                      </span>
                    </summary>
                  }
                >
                  <ul className="border-t border-slate-100">
                    {announcementMore.map((announcement) => (
                      <li key={announcement.id} className="border-b border-slate-100 last:border-b-0">
                        <ContentSummaryListLink
                          href={`/clubs/${announcement.clubId}/announcements`}
                          title={announcement.title}
                          secondaryLine={announcement.clubName}
                          timestamp={announcement.createdAtRaw}
                        />
                      </li>
                    ))}
                  </ul>
                </DashboardPersistedDetails>
              ) : null}
            </section>
          ) : null}

          <section id="my-clubs" aria-labelledby="dash-clubs-heading" className="space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 id="dash-clubs-heading" className="text-lg font-semibold tracking-tight text-slate-900 sm:text-xl">
                  My clubs
                </h2>
                <p className="mt-0.5 max-w-xl text-xs text-slate-500 sm:text-sm">Jump into a workspace.</p>
              </div>
              <Link href="/clubs/join" className="text-sm font-medium text-slate-600 hover:text-slate-900">
                Join another →
              </Link>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {clubs.map((club) => (
                <article
                  key={club.id}
                  className={`dashboard-club-card flex flex-col rounded-xl border border-slate-200 bg-white ${club.role === "officer" ? "is-officer" : ""}`}
                >
                  <div className="flex min-w-0 items-start justify-between gap-2">
                    <h3 className="truncate text-base font-semibold tracking-tight text-slate-900">{club.name}</h3>
                    <span
                      className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${
                        club.role === "officer"
                          ? "bg-blue-100 text-blue-900 ring-1 ring-blue-200/80"
                          : "bg-slate-100 text-slate-600 ring-1 ring-slate-200/80"
                      }`}
                    >
                      {club.role === "officer" ? "Officer" : "Member"}
                    </span>
                  </div>
                  <p className="mt-2 line-clamp-1 text-sm leading-snug text-slate-600">{club.description}</p>
                  {club.role === "officer" ? <ClubJoinCodeRow joinCode={club.joinCode} /> : null}
                  <Link
                    href={`/clubs/${club.id}`}
                    className="btn-primary mt-auto w-full py-2.5 text-center text-sm font-semibold"
                  >
                    Open
                  </Link>
                </article>
              ))}
            </div>
            <p className="text-center text-sm text-slate-500">
              Launch something new?{" "}
              <Link
                href="/clubs/create"
                className="font-medium text-slate-700 underline decoration-slate-300 underline-offset-2 hover:text-slate-900"
              >
                Start a club
              </Link>
            </p>
          </section>

          {officerClubs > 0 ? (
            <details className="card-surface overflow-hidden p-0 open:shadow-md" open={leadershipAlerts.length > 0}>
              <summary className="section-card-header m-0 cursor-pointer list-none p-5 sm:p-6 [&::-webkit-details-marker]:hidden">
                <div className="min-w-0 pr-8">
                  <p className="section-kicker">For officers</p>
                  <h2 className="mt-1 text-lg font-semibold tracking-tight text-slate-900">Leadership & club health</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    Follow-ups for clubs you help run—collapsed when there&apos;s nothing urgent.
                  </p>
                </div>
                <span className="badge-soft shrink-0 tabular-nums">{leadershipAlerts.length}</span>
              </summary>
              <div className="border-t border-slate-100 px-5 pb-5 pt-4 sm:px-6 sm:pb-6">
                {leadershipAlerts.length === 0 ? (
                  <div className="rounded-xl border border-emerald-200/80 bg-emerald-50/50 p-4 sm:p-5">
                    <p className="font-semibold text-slate-900">Nothing urgent right now.</p>
                    <p className="mt-1 text-sm text-slate-600">Check back after events or when you schedule new meetings.</p>
                  </div>
                ) : (
                  <div className="list-stack space-y-3">
                    {leadershipAlerts.map((alert) => (
                      <article key={alert.id} className="surface-subcard p-4">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div className="max-w-2xl min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="badge-soft">{alert.clubName}</span>
                              <span className="badge-soft">{getDashboardAlertLabel(alert.type)}</span>
                              <h3 className="text-sm font-semibold text-slate-900">{alert.title}</h3>
                            </div>
                            <p className="mt-2 text-sm leading-relaxed text-slate-600">{alert.description}</p>
                          </div>
                          <Link href={alert.ctaHref} className="btn-secondary w-full shrink-0 whitespace-nowrap sm:w-auto">
                            {alert.ctaLabel}
                          </Link>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </details>
          ) : null}
        </>
      )}
    </section>
  );
}
