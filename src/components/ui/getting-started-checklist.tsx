"use client";

type ChecklistItem = {
  id: string;
  title: string;
  description: string;
  completed: boolean;
  actionHref: string;
  actionLabel: string;
};

type GettingStartedChecklistProps = {
  clubId: string;
  membersCount: number;
  announcementsCount: number;
  eventsCount: number;
};

export function GettingStartedChecklist({
  clubId,
  membersCount,
  announcementsCount,
  eventsCount,
}: GettingStartedChecklistProps) {
  const membersCompleted = membersCount > 1;
  const announcementsCompleted = announcementsCount > 0;
  const eventsCompleted = eventsCount > 0;

  const items: ChecklistItem[] = [
    {
      id: "members",
      title: "Invite Members",
      description: "Add at least one other person to your club.",
      completed: membersCompleted,
      actionHref: "#invite-members",
      actionLabel: "Invite Now",
    },
    {
      id: "announcement",
      title: "Post First Announcement",
      description: "Share an update so members know what is happening.",
      completed: announcementsCompleted,
      actionHref: `/clubs/${clubId}/announcements`,
      actionLabel: "Post Update",
    },
    {
      id: "event",
      title: "Create First Event",
      description: "Schedule a meeting or activity for your members.",
      completed: eventsCompleted,
      actionHref: `/clubs/${clubId}/events#create-event`,
      actionLabel: "Create Event",
    },
  ];

  const totalCompleted = items.filter((item) => item.completed).length;
  const progressPercent = (totalCompleted / items.length) * 100;

  return (
    <div className="card-surface p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="section-kicker">Getting Started</p>
          <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">
            Set up your club
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Complete these steps to get your club running.
          </p>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-slate-900">
            {totalCompleted}/{items.length}
          </p>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">done</p>
        </div>
      </div>

      <div className="mt-5 mb-5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
        <div
          className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-[width] duration-300"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      <ul className="space-y-2.5">
        {items.map((item) => (
          <li key={item.id} className="flex items-start gap-4 rounded-xl border border-slate-100 bg-slate-50/60 px-4 py-3">
            <div className="mt-0.5 flex-shrink-0">
              {item.completed ? (
                <div className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500">
                  <svg className="h-3 w-3 text-white" viewBox="0 0 12 12" fill="none">
                    <path d="M2 6l3 3 5-5" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              ) : (
                <div className="h-5 w-5 rounded-full border-2 border-slate-300 bg-white" />
              )}
            </div>
            <div className="min-w-0 flex-1">
              <p className={`text-sm font-semibold ${item.completed ? "text-slate-400 line-through" : "text-slate-900"}`}>
                {item.title}
              </p>
              <p className="mt-0.5 text-sm text-slate-500">{item.description}</p>
            </div>
            {!item.completed && (
              <a
                href={item.actionHref}
                className="mt-0.5 flex-shrink-0 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 whitespace-nowrap"
              >
                {item.actionLabel}
              </a>
            )}
          </li>
        ))}
      </ul>

      {totalCompleted === items.length && (
        <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3">
          <p className="text-sm font-semibold text-emerald-900">
            Your club is all set. Keep the momentum going.
          </p>
        </div>
      )}
    </div>
  );
}
