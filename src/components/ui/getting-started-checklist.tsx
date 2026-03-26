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
  membersCount: number;
  announcementsCount: number;
  eventsCount: number;
};

export function GettingStartedChecklist({
  membersCount,
  announcementsCount,
  eventsCount,
}: GettingStartedChecklistProps) {
  // Checklist completion logic
  // Members: count > 1 (creator always exists, so we need at least one more)
  const membersCompleted = membersCount > 1;
  // Announcements: at least one posted
  const announcementsCompleted = announcementsCount > 0;
  // Events: at least one created
  const eventsCompleted = eventsCount > 0;

  const items: ChecklistItem[] = [
    {
      id: "members",
      title: "Add Members",
      description: "Invite people to join your club.",
      completed: membersCompleted,
      actionHref: `#members`,
      actionLabel: "Invite Members",
    },
    {
      id: "announcement",
      title: "Post First Announcement",
      description: "Share an update with your club.",
      completed: announcementsCompleted,
      actionHref: `#announcements`,
      actionLabel: "Post Announcement",
    },
    {
      id: "event",
      title: "Create First Event",
      description: "Schedule something for your members.",
      completed: eventsCompleted,
      actionHref: `#events`,
      actionLabel: "Create Event",
    },
  ];

  const totalCompleted = items.filter((item) => item.completed).length;
  const progressPercent = (totalCompleted / items.length) * 100;

  return (
    <div className="card-surface p-6">
      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <p className="section-kicker">Getting Started</p>
          <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">
            Set up your club
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Complete these steps to get your club ready.
          </p>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-slate-900">
            {totalCompleted}/{items.length}
          </p>
          <p className="text-xs text-slate-600">complete</p>
        </div>
      </div>

      {/* Progress bar */}
      <div className="mb-6 h-2 w-full rounded-full bg-slate-200 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-blue-500 to-indigo-600 transition-all duration-300"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* Checklist items */}
      <ul className="space-y-3">
        {items.map((item) => (
          <li key={item.id} className="flex items-start gap-4">
            <div className="mt-0.5 flex-shrink-0">
              {item.completed ? (
                <div className="flex h-5 w-5 items-center justify-center rounded-full bg-green-600">
                  <span className="text-xs font-bold text-white">✓</span>
                </div>
              ) : (
                <div className="h-5 w-5 rounded-full border-2 border-slate-300" />
              )}
            </div>
            <div className="min-w-0 flex-1">
              <p
                className={`font-medium ${
                  item.completed
                    ? "text-slate-500 line-through"
                    : "text-slate-900"
                }`}
              >
                {item.title}
              </p>
              <p className="mt-0.5 text-sm text-slate-600">
                {item.description}
              </p>
            </div>
            {!item.completed && (
              <a
                href={item.actionHref}
                className="mt-0.5 inline-block flex-shrink-0 rounded-md bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-200 transition whitespace-nowrap"
              >
                {item.actionLabel}
              </a>
            )}
          </li>
        ))}
      </ul>

      {totalCompleted === items.length && (
        <div className="mt-6 rounded-lg bg-green-50 border border-green-200 p-4">
          <p className="text-sm font-semibold text-green-900">
            ✓ Your club is all set! Time to invite more people.
          </p>
        </div>
      )}
    </div>
  );
}
