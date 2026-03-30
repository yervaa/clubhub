import { AnnouncementGenerator } from "@/components/ui/announcement-generator";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
import { createAnnouncementAction } from "@/app/(app)/clubs/actions";
import type { ClubDetail } from "@/lib/clubs/queries";

type ClubAnnouncementsPermissions = {
  canPostAnnouncements: boolean;
  canEditAnnouncements?: boolean;
  canDeleteAnnouncements?: boolean;
};

type ClubAnnouncementsSectionProps = {
  club: ClubDetail;
  permissions?: ClubAnnouncementsPermissions;
  query: {
    annError?: string;
    annSuccess?: string;
  };
};

export function ClubAnnouncementsSection({ club, query, permissions }: ClubAnnouncementsSectionProps) {
  const count = club.announcements.length;
  const latestAnnouncement = club.announcements[0] ?? null;
  const olderAnnouncements = club.announcements.slice(1);

  // RBAC-based check with legacy officer fallback for backward compatibility.
  const legacyIsOfficer = club.currentUserRole === "officer";
  const canPostAnnouncements = permissions?.canPostAnnouncements ?? legacyIsOfficer;

  return (
    <section className="space-y-4 lg:space-y-6">

      <header className="card-surface border border-slate-200/90 bg-gradient-to-br from-slate-50 to-amber-50/80 p-4 shadow-sm sm:p-6 lg:border-2 lg:p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Announcements</p>
          <h1 className="section-title mt-1 text-xl sm:mt-2 sm:text-3xl md:text-4xl">Announcements</h1>
          <p className="section-subtitle mt-2 max-w-2xl text-sm sm:mt-3 sm:text-base sm:text-lg text-slate-700">
            {canPostAnnouncements
              ? "Post updates, reminders, and important news to keep everyone in the loop."
              : "Stay up to date with the latest news and updates from your club."}
          </p>

          <div className="mt-4 flex flex-col gap-3 sm:mt-6 sm:flex-row sm:flex-wrap sm:items-center sm:gap-8 lg:mt-8">
            <div>
              <p className="text-2xl font-bold text-slate-900">{count}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {count === 1 ? "Announcement" : "Announcements"}
              </p>
            </div>

            {latestAnnouncement && (
              <>
                <div className="hidden h-8 w-px bg-slate-200 sm:block" aria-hidden />
                <div className="min-w-0 max-w-full sm:max-w-[18rem]">
                  <p className="truncate text-base font-bold text-slate-900">{latestAnnouncement.title}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                    Latest · {latestAnnouncement.createdAt}
                  </p>
                </div>
              </>
            )}
          </div>

          {canPostAnnouncements && (
            <div className="mt-4 sm:mt-6 lg:mt-8">
              <a
                href="#post-announcement"
                className="btn-primary block w-full px-6 py-3 text-center text-base font-semibold sm:inline-block sm:w-auto"
              >
                Post Announcement
              </a>
            </div>
          )}
        </div>
      </header>

      {/* Feedback messages */}
      {query.annSuccess ? <p className="alert-success">{query.annSuccess}</p> : null}
      {query.annError ? <p className="alert-error">{query.annError}</p> : null}

      {/* Post form — requires announcements.create permission */}
      {canPostAnnouncements && (
        <section id="post-announcement" className="card-surface p-4 sm:p-6">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Post</p>
              <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">New Announcement</h2>
              <p className="mt-1 text-sm text-slate-600">
                Share meeting changes, reminders, or important news with everyone in the club.
              </p>
            </div>
          </div>

          <form action={createAnnouncementAction} className="mt-5 space-y-4">
            <input type="hidden" name="club_id" value={club.id} />
            <AnnouncementGenerator
              titleSelector='input[name="title"]'
              contentSelector='textarea[name="content"]'
            />
            <div>
              <label htmlFor="ann-title" className="mb-1.5 block text-sm font-medium text-slate-700">
                Title
              </label>
              <input
                id="ann-title"
                name="title"
                type="text"
                required
                className="input-control"
                placeholder="Announcement title"
              />
            </div>
            <div>
              <label htmlFor="ann-content" className="mb-1.5 block text-sm font-medium text-slate-700">
                Content
              </label>
              <textarea
                id="ann-content"
                name="content"
                rows={4}
                required
                className="textarea-control"
                placeholder="Write your announcement..."
              />
            </div>
            <button type="submit" className="btn-primary">
              Post Announcement
            </button>
          </form>
        </section>
      )}

      {/* Announcements — empty state */}
      {count === 0 ? (
        <div className="card-surface p-10 text-center" id="announcements">
          <div className="mx-auto max-w-xs">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-amber-100">
              <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
              </svg>
            </div>
            <h3 className="mt-4 text-base font-semibold text-slate-900">No announcements yet</h3>
            <p className="mt-1 text-sm text-slate-500">
              {canPostAnnouncements
                ? "Use the form above to post your first update."
                : "Your club officers will post updates here."}
            </p>
            {canPostAnnouncements && (
              <ScrollToInputButton
                inputSelector='input[name="title"]'
                className="btn-secondary mt-4"
              >
                Write First Announcement
              </ScrollToInputButton>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-4" id="announcements">

          {/* Latest announcement — visually elevated */}
          {latestAnnouncement && (
            <article className="ann-latest-card">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="feedback-pill feedback-pill-fresh">Latest</span>
                    <span className="text-xs text-slate-400">{latestAnnouncement.createdAt}</span>
                  </div>
                  <h3 className="mt-2 text-lg font-bold tracking-tight text-slate-900 sm:mt-3 sm:text-xl">
                    {latestAnnouncement.title}
                  </h3>
                </div>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-slate-600 sm:mt-4 sm:leading-7">{latestAnnouncement.content}</p>
            </article>
          )}

          {/* Announcement history */}
          {olderAnnouncements.length > 0 && (
            <div className="card-surface p-4 sm:p-5">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">History</p>
                  <h2 className="mt-0.5 text-sm font-semibold tracking-tight text-slate-900 sm:mt-1 sm:text-base">Older posts</h2>
                </div>
                <span className="badge-soft">{olderAnnouncements.length}</span>
              </div>
              <div className="mt-3 divide-y divide-slate-100 sm:mt-4 sm:flex sm:flex-col sm:gap-3 sm:divide-y-0">
                {olderAnnouncements.map((announcement) => (
                  <article key={announcement.id} className="py-3 first:pt-0 last:pb-0 sm:surface-subcard sm:p-4 sm:py-4">
                    <div className="flex flex-wrap items-start justify-between gap-1 sm:gap-2">
                      <h4 className="text-sm font-semibold text-slate-900">{announcement.title}</h4>
                      <span className="whitespace-nowrap text-[11px] text-slate-400 sm:text-xs">{announcement.createdAt}</span>
                    </div>
                    <p className="mt-1.5 line-clamp-3 text-xs leading-relaxed text-slate-600 sm:mt-2 sm:line-clamp-none sm:text-sm sm:leading-6">
                      {announcement.content}
                    </p>
                  </article>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

    </section>
  );
}
