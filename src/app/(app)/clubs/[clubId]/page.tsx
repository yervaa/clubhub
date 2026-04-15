import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubAttentionNeededSection } from "@/components/ui/club-attention-needed-section";
import { ActivityFeed } from "@/components/ui/activity-feed";
import { EventMetaRow } from "@/components/ui/event-summary";
import { getClubDetailForOverviewForCurrentUser } from "@/lib/clubs/queries";
import { getMyClubTasks } from "@/lib/tasks/queries";
import { CardSection, PageEmptyState, SectionHeader } from "@/components/ui/page-patterns";
import { PageIntro } from "@/components/ui/page-intro";
import { getClubActivityFeed } from "@/lib/activity/queries";

type ClubOverviewPageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubOverviewPage({ params }: ClubOverviewPageProps) {
  const { clubId } = await params;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions, myTasks, activityItems] = await Promise.all([
    getClubDetailForOverviewForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
    getMyClubTasks(clubId, user.id),
    getClubActivityFeed(clubId, 10),
  ]);

  if (!club) {
    notFound();
  }

  // Derive permission booleans for UI control visibility.
  const canInviteMembers = userPermissions.has("members.invite");
  const canCreateEvents = userPermissions.has("events.create");
  const canPostAnnouncements = userPermissions.has("announcements.create");
  const canMarkAttendance = userPermissions.has("attendance.mark");
  // Show management alerts when the user has at least one management-facing permission.
  const showManagementAlerts = canCreateEvents || canPostAnnouncements || canMarkAttendance;

  const memberCount = club.memberCount;
  const now = new Date();
  const nextEvent = [...club.events]
    .filter((event) => event.eventDateRaw.getTime() > now.getTime())
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0] ?? null;
  const latestAnnouncement = club.announcements[0] ?? null;
  const hasClubDescription = club.description.trim().length > 0;
  const onboardingSteps = [
    {
      id: "details",
      title: "Complete club details",
      description: "Add a clear description so new members know what your club is about.",
      done: hasClubDescription,
      href: `/clubs/${club.id}/settings/club`,
      cta: "Edit details",
    },
    {
      id: "members",
      title: "Invite members",
      description: "Bring in at least one more member so your club starts feeling social.",
      done: memberCount > 1,
      href: `/clubs/${club.id}/members#invite-members`,
      cta: "Invite now",
    },
    {
      id: "announcement",
      title: "Post first announcement",
      description: "Share one update so everyone sees the communication flow.",
      done: club.announcements.length > 0,
      href: `/clubs/${club.id}/announcements`,
      cta: "Post update",
    },
    {
      id: "event",
      title: "Create first event",
      description: "Schedule a meeting or activity to start RSVPs and engagement.",
      done: club.events.length > 0,
      href: `/clubs/${club.id}/events#create-event`,
      cta: "Create event",
    },
    {
      id: "attendance",
      title: "Mark attendance",
      description: "After your first event, mark attendance to unlock insights.",
      done: club.totalTrackedEvents > 0,
      href: `/clubs/${club.id}/events#recent`,
      cta: "Mark attendance",
    },
  ];
  const onboardingDone = onboardingSteps.filter((step) => step.done).length;
  const onboardingPercent = Math.round((onboardingDone / onboardingSteps.length) * 100);
  const showOnboardingChecklist = onboardingDone < onboardingSteps.length;

  return (
    <section className="space-y-5 lg:space-y-8">
      <PageIntro
        kicker="Overview"
        title={club.name}
        description={club.description}
        actions={
          canInviteMembers || canCreateEvents ? (
            <>
              {canInviteMembers ? (
                <Link href={`/clubs/${club.id}/members#invite-members`} className="btn-primary">
                  Invite Members
                </Link>
              ) : null}
              {canCreateEvents ? (
                <Link href={`/clubs/${club.id}/events#create-event`} className="btn-secondary">
                  Create Event
                </Link>
              ) : null}
            </>
          ) : undefined
        }
      />

      <CardSection className="bg-gradient-to-br from-slate-50 to-blue-50/40">
        <SectionHeader
          kicker="Snapshot"
          title="Club status at a glance"
          description="Members, your role, and activity state."
        />
        <div className="mt-4 grid grid-cols-3 gap-2 sm:mt-6 sm:grid-cols-3 sm:gap-4 md:gap-6">
            <div className="flex items-center gap-2 rounded-lg border border-white/60 bg-white/50 px-2 py-2 sm:gap-3 sm:border-0 sm:bg-transparent sm:px-0 sm:py-0">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-blue-100 sm:h-12 sm:w-12">
                <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                </svg>
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 sm:text-sm sm:normal-case sm:tracking-normal">Members</p>
                <p className="text-lg font-bold tabular-nums text-slate-900 sm:text-xl">{memberCount}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 rounded-lg border border-white/60 bg-white/50 px-2 py-2 sm:gap-3 sm:border-0 sm:bg-transparent sm:px-0 sm:py-0">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-green-100 sm:h-12 sm:w-12">
                <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 sm:text-sm sm:normal-case sm:tracking-normal">Role</p>
                <p className="truncate text-lg font-bold capitalize text-slate-900 sm:text-xl">{club.currentUserRole}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 rounded-lg border border-white/60 bg-white/50 px-2 py-2 sm:gap-3 sm:border-0 sm:bg-transparent sm:px-0 sm:py-0">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-purple-100 sm:h-12 sm:w-12">
                <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 sm:text-sm sm:normal-case sm:tracking-normal">Status</p>
                <p className="text-lg font-bold text-slate-900 sm:text-xl">
                  {club.events.length > 0 ? "Active" : "Starting"}
                </p>
              </div>
            </div>
          </div>
      </CardSection>

      {showOnboardingChecklist ? (
        <CardSection>
          <SectionHeader
            kicker="Getting started"
            title="Launch checklist"
            description="Quick wins to make this club feel active for members immediately."
            action={<span className="badge-soft">{onboardingDone}/{onboardingSteps.length} complete</span>}
          />
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-100">
            <div
              className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-[width] duration-300"
              style={{ width: `${onboardingPercent}%` }}
            />
          </div>
          <ul className="mt-4 space-y-2">
            {onboardingSteps.map((step) => (
              <li
                key={step.id}
                className="flex items-start justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/70 px-3 py-2.5"
              >
                <div className="min-w-0">
                  <p className={`text-sm font-semibold ${step.done ? "text-slate-500 line-through" : "text-slate-900"}`}>
                    {step.title}
                  </p>
                  <p className="mt-0.5 text-xs text-slate-600">{step.description}</p>
                </div>
                {step.done ? (
                  <span className="shrink-0 rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800">
                    Done
                  </span>
                ) : (
                  <Link href={step.href} className="btn-secondary shrink-0 text-xs">
                    {step.cta}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </CardSection>
      ) : null}

      {/* Important now — lighter tiles on mobile */}
      <CardSection className="shadow-sm lg:shadow-[var(--shadow-soft)]">
        <SectionHeader
          kicker="Now"
          title="What matters"
          description="Next event, latest announcement, task load, and quick health signals."
        />

        <div className="mt-3 grid grid-cols-1 gap-2 sm:mt-4 sm:grid-cols-2 sm:gap-3 lg:grid-cols-4 lg:gap-4">
          <div className="rounded-lg border border-slate-100 bg-slate-50/50 p-3 sm:surface-subcard sm:border-l-4 sm:border-blue-500 sm:bg-white sm:p-4">
            <div className="flex items-start gap-2.5 sm:gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-100 sm:h-9 sm:w-9">
                <svg className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Next Event</p>
                <p className="mt-1 text-base font-semibold leading-snug text-slate-900">
                  {nextEvent ? nextEvent.title : "No upcoming events"}
                </p>
                {nextEvent ? (
                  <>
                    <p className="mt-0.5 text-xs text-slate-500">{nextEvent.eventType}</p>
                    <div className="mt-2">
                      <EventMetaRow at={nextEvent.eventDateRaw} location={nextEvent.location} compact />
                    </div>
                  </>
                ) : (
                  <p className="mt-1 text-xs text-slate-500">Schedule one on the Events page.</p>
                )}
              </div>
            </div>
          </div>

          {/* Latest announcement */}
          <div className="rounded-lg border border-slate-100 bg-slate-50/50 p-3 sm:surface-subcard sm:border-l-4 sm:border-amber-500 sm:bg-white sm:p-4">
            <div className="flex items-start gap-2.5 sm:gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-100 sm:h-9 sm:w-9">
                <svg className="h-5 w-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Latest Announcement</p>
                <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                  {latestAnnouncement ? latestAnnouncement.title : "No announcements yet"}
                </p>
                {latestAnnouncement ? (
                  <p className="mt-1 text-xs text-slate-500 line-clamp-2">{latestAnnouncement.content}</p>
                ) : (
                  <p className="mt-1 text-xs text-slate-500">Post one on the Announcements page.</p>
                )}
              </div>
            </div>
          </div>

          {/* My Tasks */}
          <div className="rounded-lg border border-slate-100 bg-slate-50/50 p-3 sm:surface-subcard sm:border-l-4 sm:border-emerald-500 sm:bg-white sm:p-4">
            <div className="flex items-start gap-2.5 sm:gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-100 sm:h-9 sm:w-9">
                <svg className="h-5 w-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">My Tasks</p>
                {myTasks.length > 0 ? (
                  <>
                    <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                      {myTasks.length} open task{myTasks.length !== 1 ? "s" : ""}
                    </p>
                    <p className="mt-1 text-xs text-slate-500 truncate">
                      {myTasks.filter((t) => t.isOverdue).length > 0
                        ? `${myTasks.filter((t) => t.isOverdue).length} overdue`
                        : myTasks[0]?.title}
                    </p>
                  </>
                ) : (
                  <>
                    <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">All caught up</p>
                    <p className="mt-1 text-xs text-slate-500">No tasks assigned to you.</p>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Key stats */}
          <div className="rounded-lg border border-slate-100 bg-slate-50/50 p-3 sm:surface-subcard sm:border-l-4 sm:border-purple-500 sm:bg-white sm:p-4">
            <div className="flex items-start gap-2.5 sm:gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-100 sm:h-9 sm:w-9">
                <svg className="h-5 w-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Key Stats</p>
                <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                  {club.events.length} events · {club.announcements.length} updates
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {club.totalTrackedEvents} tracked · {club.clubAverageAttendance}% avg attendance
                </p>
              </div>
            </div>
          </div>
        </div>
      </CardSection>

      <CardSection>
        <SectionHeader
          kicker="Tools"
          title="Secondary workspace tools"
          description="Power features stay available without crowding the main overview."
        />
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <Link
            href={`/clubs/${club.id}/tasks`}
            className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5 text-sm font-medium text-slate-800 transition hover:bg-slate-100"
          >
            Tasks {myTasks.length > 0 ? `(${myTasks.length} open)` : ""}
          </Link>
          <Link
            href={`/clubs/${club.id}/members/volunteer-hours`}
            className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5 text-sm font-medium text-slate-800 transition hover:bg-slate-100"
          >
            Volunteer hours
          </Link>
        </div>
        {myTasks.length === 0 ? (
          <div className="mt-3">
            <PageEmptyState title="No open tasks" copy="You can still open Tasks to create or review assignments." />
          </div>
        ) : null}
      </CardSection>

      {/* Attention Needed — shown to users with management permissions */}
      {showManagementAlerts && (
        <ClubAttentionNeededSection clubId={club.id} alerts={club.attentionAlerts} />
      )}

      {/* Recent Activity — visible to all members */}
      <ActivityFeed
        items={activityItems.slice(0, 8)}
        title="Recent activity"
        description="Latest actions in this club."
        viewMoreHref="/activity"
        emptyHint="As members RSVP, officers post updates, and attendance gets marked, activity shows up here."
        emptyAction={
          <Link href={`/clubs/${club.id}/announcements`} className="btn-primary">
            Post first update
          </Link>
        }
      />
    </section>
  );
}
