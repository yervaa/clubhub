import { AnnouncementComposerCollapsible } from "@/components/ui/announcement-composer-collapsible";
import { AnnouncementGenerator } from "@/components/ui/announcement-generator";
import { AnnouncementFeedItem } from "@/components/ui/announcement-feed-item";
import { ClubPageStickyActions } from "@/components/ui/club-page-sticky-actions";
import { PollOptionFields } from "@/components/ui/poll-option-fields";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
import { createAnnouncementAction } from "@/app/(app)/clubs/actions";
import type { ClubDetail } from "@/lib/clubs/queries";
import { CardSection, PageEmptyState, SectionHeader } from "@/components/ui/page-patterns";
import { PageIntro } from "@/components/ui/page-intro";

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

      <PageIntro
        title="Announcements"
        description={
          canPostAnnouncements
            ? "Post updates, polls, and files while keeping the feed easy for members to scan."
            : "Latest news and updates from your club."
        }
        actions={<span className="badge-soft tabular-nums">{statsParts.join(" · ")}</span>}
      />

      {query.annSuccess ? <p className="alert-success">{query.annSuccess}</p> : null}
      {query.annError ? <p className="alert-error">{query.annError}</p> : null}

      {canPostAnnouncements && (
        <AnnouncementComposerCollapsible defaultOpen={count === 0}>
          <CardSection className="sm:p-6">
            <SectionHeader
              kicker="Compose"
              title="New announcement"
              description="Members are notified when a post goes live. Polls, attachments, and scheduling are optional."
            />

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
                  className="input-control min-h-11 w-full sm:max-w-md"
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
                  className="block w-full text-sm text-slate-600 file:mr-3 file:min-h-11 file:rounded-lg file:border-0 file:bg-slate-900 file:px-3 file:py-2 file:text-sm file:font-semibold file:text-white hover:file:bg-slate-800"
                />
                <p className="mt-1 text-xs text-slate-500">Up to 5 files, 5 MB each — images or PDF.</p>
              </div>

              <button type="submit" className="btn-primary w-full sm:w-auto">
                Publish
              </button>
            </form>
          </CardSection>
        </AnnouncementComposerCollapsible>
      )}

      {count === 0 ? (
        <div id="announcements">
          <PageEmptyState
            title="No announcements yet"
            copy={
              canPostAnnouncements
                ? "Use the composer above to post the first update for this club."
                : "Club officers will post updates here."
            }
            action={
              canPostAnnouncements ? (
                <ScrollToInputButton inputSelector='input[name="title"]' className="btn-secondary">
                  Write first announcement
                </ScrollToInputButton>
              ) : null
            }
          />
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
            <CardSection>
              <SectionHeader
                kicker="History"
                title="Older posts"
                action={<span className="badge-soft">{olderAnnouncements.length}</span>}
              />
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
            </CardSection>
          )}
        </div>
      )}
    </section>
  );
}
