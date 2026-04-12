import { AnnouncementComposerCollapsible } from "@/components/ui/announcement-composer-collapsible";
import { AnnouncementGenerator } from "@/components/ui/announcement-generator";
import { AnnouncementFeedItem } from "@/components/ui/announcement-feed-item";
import { ClubPageStickyActions } from "@/components/ui/club-page-sticky-actions";
import { PollOptionFields } from "@/components/ui/poll-option-fields";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
import { createAnnouncementAction } from "@/app/(app)/clubs/actions";
import type { ClubDetail } from "@/lib/clubs/queries";

type ClubAnnouncementsPermissions = {
  canPostAnnouncements: boolean;
  canEditAnnouncements?: boolean;
  canDeleteAnnouncements?: boolean;
  /** Can expand “who read this” (officers + announcements.edit). */
  canViewReadersList?: boolean;
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

  const legacyIsOfficer = club.currentUserRole === "officer";
  const canPostAnnouncements = permissions?.canPostAnnouncements ?? legacyIsOfficer;
  const canViewReadersList =
    permissions?.canViewReadersList ??
    ((permissions?.canEditAnnouncements ?? false) || legacyIsOfficer);

  const statsParts: string[] = [`${count} post${count === 1 ? "" : "s"}`];
  if (latestAnnouncement) {
    statsParts.push(`Latest: ${latestAnnouncement.title}`);
  }

  return (
    <section className={`space-y-4 lg:space-y-6 ${canPostAnnouncements ? "pb-24 lg:pb-0" : ""}`}>
      <ClubPageStickyActions
        visible={canPostAnnouncements}
        href="#post-announcement"
        label="Post announcement"
      />

      <header className="card-surface border border-slate-200/90 bg-gradient-to-br from-slate-50 to-amber-50/80 p-4 shadow-sm sm:p-5 lg:border-2 lg:p-6">
        <div className="max-w-4xl">
          <h1 className="section-title text-xl sm:text-2xl md:text-3xl">Announcements</h1>
          <p className="section-subtitle mt-1.5 hidden max-w-2xl text-sm text-slate-600 sm:mt-2 sm:block sm:text-base">
            {canPostAnnouncements
              ? "Post updates, polls, and files — see read receipts when you have editor access."
              : "Latest news and updates from your club."}
          </p>

          <p className="mt-3 text-xs font-medium leading-snug text-slate-600 sm:text-sm">
            <span className="tabular-nums text-slate-800">{statsParts.join(" · ")}</span>
          </p>
        </div>
      </header>

      {query.annSuccess ? <p className="alert-success">{query.annSuccess}</p> : null}
      {query.annError ? <p className="alert-error">{query.annError}</p> : null}

      {canPostAnnouncements && (
        <AnnouncementComposerCollapsible defaultOpen={count === 0}>
          <section className="card-surface p-4 sm:p-6">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Compose</p>
                <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">New announcement</h2>
                <p className="mt-1 text-sm text-slate-600">
                  Members are notified when the post goes live. Optional poll, attachments, or schedule below.
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

              <div>
                <label htmlFor="ann-schedule" className="mb-1.5 block text-sm font-medium text-slate-700">
                  Schedule publish (optional)
                </label>
                <input
                  id="ann-schedule"
                  name="scheduled_for"
                  type="datetime-local"
                  className="input-control max-w-md"
                />
                <p className="mt-1 text-xs text-slate-500">
                  Leave empty to post immediately. Scheduled posts stay hidden until they publish.
                </p>
              </div>

              <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4">
                <p className="text-sm font-semibold text-slate-900">Poll (optional)</p>
                <p className="mt-0.5 text-xs text-slate-500">
                  Add a question to show voting buttons. Leave blank for a normal announcement.
                </p>
                <div className="mt-3">
                  <label htmlFor="ann-poll-q" className="mb-1.5 block text-sm font-medium text-slate-700">
                    Poll question
                  </label>
                  <input
                    id="ann-poll-q"
                    name="poll_question"
                    type="text"
                    className="input-control"
                    placeholder="e.g. Which meeting time works best?"
                    maxLength={500}
                  />
                </div>
                <div className="mt-3">
                  <PollOptionFields />
                </div>
              </div>

              <div>
                <label htmlFor="ann-files" className="mb-1.5 block text-sm font-medium text-slate-700">
                  Attachments (optional)
                </label>
                <input
                  id="ann-files"
                  name="attachments"
                  type="file"
                  multiple
                  accept="image/jpeg,image/png,image/gif,image/webp,application/pdf"
                  className="block w-full text-sm text-slate-600 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-900 file:px-3 file:py-2 file:text-sm file:font-semibold file:text-white hover:file:bg-slate-800"
                />
                <p className="mt-1 text-xs text-slate-500">Up to 5 files, 5 MB each — images or PDF.</p>
              </div>

              <button type="submit" className="btn-primary">
                Publish
              </button>
            </form>
          </section>
        </AnnouncementComposerCollapsible>
      )}

      {count === 0 ? (
        <div className="card-surface p-10 text-center" id="announcements">
          <div className="mx-auto max-w-xs">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-amber-100">
              <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"
                />
              </svg>
            </div>
            <h3 className="mt-4 text-base font-semibold text-slate-900">No announcements yet</h3>
            <p className="mt-1 text-sm text-slate-500">
              {canPostAnnouncements
                ? "Use the composer above to post your first update."
                : "Your club officers will post updates here."}
            </p>
            {canPostAnnouncements && (
              <ScrollToInputButton inputSelector='input[name="title"]' className="btn-secondary mt-4">
                Write first announcement
              </ScrollToInputButton>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-4" id="announcements">
          {latestAnnouncement ? (
            <AnnouncementFeedItem
              announcement={latestAnnouncement}
              canOpenReadersList={canViewReadersList}
              variant="featured"
            />
          ) : null}

          {olderAnnouncements.length > 0 && (
            <div className="card-surface p-4 sm:p-5">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">History</p>
                  <h2 className="mt-0.5 text-sm font-semibold tracking-tight text-slate-900 sm:mt-1 sm:text-base">
                    Older posts
                  </h2>
                </div>
                <span className="badge-soft">{olderAnnouncements.length}</span>
              </div>
              <div className="mt-3 divide-y divide-slate-100 sm:mt-4 sm:flex sm:flex-col sm:gap-3 sm:divide-y-0">
                {olderAnnouncements.map((announcement) => (
                  <AnnouncementFeedItem
                    key={announcement.id}
                    announcement={announcement}
                    canOpenReadersList={canViewReadersList}
                    variant="compact"
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
