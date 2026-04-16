"use client";

import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  getAnnouncementReadersAction,
  markAnnouncementReadAction,
  votePollAnnouncementAction,
  type AnnouncementReaderRow,
} from "@/app/(app)/clubs/announcement-communication-actions";
import { AnnouncementManagementControls } from "@/components/ui/announcement-management-controls";
import type { ClubAnnouncement } from "@/lib/clubs/queries";

type AnnouncementFeedItemProps = {
  clubId: string;
  announcement: ClubAnnouncement;
  /** Officers or members with announcements.edit may open the reader list. */
  canOpenReadersList: boolean;
  canEditAnnouncement?: boolean;
  canDeleteAnnouncement?: boolean;
  variant: "featured" | "compact";
};

function isImageMime(mime: string): boolean {
  return mime.startsWith("image/");
}

const READ_MORE_MIN_CHARS = 160;

function contentNeedsToggle(text: string): boolean {
  const t = text.trim();
  if (t.length >= READ_MORE_MIN_CHARS) return true;
  return t.split(/\r?\n/).filter(Boolean).length > 3;
}

export function AnnouncementFeedItem({
  clubId,
  announcement,
  canOpenReadersList,
  canEditAnnouncement = false,
  canDeleteAnnouncement = false,
  variant,
}: AnnouncementFeedItemProps) {
  const router = useRouter();
  const rootRef = useRef<HTMLElement | null>(null);
  const markedRef = useRef(false);
  const [readStatsOpen, setReadStatsOpen] = useState(false);
  const [readers, setReaders] = useState<AnnouncementReaderRow[] | null>(null);
  const [readersLoading, setReadersLoading] = useState(false);
  const [pending, startTransition] = useTransition();
  const [localVoteState, setLocalVoteState] = useState<{ announcementId: string; vote: number | null } | null>(null);
  const [bodyExpanded, setBodyExpanded] = useState(false);
  const localVoteIndex =
    localVoteState?.announcementId === announcement.id
      ? localVoteState.vote
      : (announcement.userPollVoteIndex ?? null);

  const readCount = announcement.readCount ?? 0;
  const totalMembers = announcement.totalMembers ?? 0;
  const hasPoll =
    Boolean(announcement.pollQuestion?.trim()) &&
    Array.isArray(announcement.pollOptions) &&
    announcement.pollOptions.length >= 2;

  const recordRead = useCallback(() => {
    if (markedRef.current) return;
    if (!announcement.isPublished) return;
    markedRef.current = true;
    void markAnnouncementReadAction(announcement.id);
  }, [announcement.id, announcement.isPublished]);

  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;

    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting && e.intersectionRatio >= 0.25) {
            recordRead();
            obs.disconnect();
            break;
          }
        }
      },
      { threshold: [0, 0.25, 0.5, 1] },
    );

    obs.observe(el);
    return () => obs.disconnect();
  }, [recordRead]);

  async function ensureReadersLoaded() {
    if (!canOpenReadersList) return;
    if (readers !== null) return;
    setReadersLoading(true);
    const res = await getAnnouncementReadersAction(announcement.id);
    setReadersLoading(false);
    if (res.ok) {
      setReaders(res.readers);
    } else {
      setReaders([]);
    }
  }

  function toggleReadStats() {
    const next = !readStatsOpen;
    setReadStatsOpen(next);
    if (next && canOpenReadersList) {
      void ensureReadersLoaded();
    }
  }

  const pollTallies = announcement.pollTallies ?? [];
  const totalVotes = announcement.totalPollVotes ?? 0;
  const hasVoted = localVoteIndex !== null;

  function vote(idx: number) {
    startTransition(async () => {
      const res = await votePollAnnouncementAction(announcement.id, idx);
      if (res.ok) {
        setLocalVoteState({ announcementId: announcement.id, vote: idx });
        router.refresh();
      }
    });
  }

  const scheduledLabel =
    announcement.scheduledFor && !announcement.isPublished
      ? `Scheduled · ${new Date(announcement.scheduledFor).toLocaleString()}`
      : null;

  const showReadRow = announcement.isPublished && totalMembers > 0;
  const expandableBody = contentNeedsToggle(announcement.content);
  const canManageAnnouncement = canEditAnnouncement || canDeleteAnnouncement;

  const cardClass =
    variant === "featured"
      ? `${announcement.isUrgent ? "ring-2 ring-rose-200" : ""} ann-latest-card`
      : `${announcement.isUrgent ? "border-rose-200 bg-rose-50/50" : "border-slate-100 bg-white/90"} rounded-xl border p-4 shadow-sm sm:border-slate-200/90 sm:p-5`;

  const titleClass =
    variant === "featured"
      ? "mt-2 text-lg font-bold tracking-tight text-slate-900 sm:text-xl"
      : "mt-1.5 text-base font-semibold tracking-tight text-slate-900";

  return (
    <article ref={rootRef} id={`announcement-${announcement.id}`} className={cardClass}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
            {variant === "featured" ? (
              <span className="feedback-pill feedback-pill-fresh">Latest</span>
            ) : null}
            {scheduledLabel ? (
              <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-800">
                {scheduledLabel}
              </span>
            ) : null}
            {announcement.approvalStatus === "pending" ? (
              <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-900">
                Pending approval
              </span>
            ) : announcement.approvalStatus === "rejected" ? (
              <span className="rounded-full bg-rose-100 px-2 py-0.5 text-[11px] font-semibold text-rose-900">Not approved</span>
            ) : !announcement.isPublished ? (
              <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-semibold text-amber-800">Draft</span>
            ) : (
              <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-semibold text-emerald-800">Published</span>
            )}
            {announcement.isPinned ? (
              <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-[11px] font-semibold text-indigo-800">Pinned</span>
            ) : null}
            {announcement.isUrgent ? (
              <span className="rounded-full bg-rose-100 px-2 py-0.5 text-[11px] font-semibold text-rose-800">Urgent</span>
            ) : null}
            <span className="text-slate-400">{announcement.createdAt}</span>
          </div>
          <h3 className={titleClass}>{announcement.title}</h3>
          {announcement.approvalStatus === "rejected" && announcement.rejectionReason ? (
            <p className="mt-2 rounded-lg border border-amber-200 bg-amber-50/90 px-3 py-2 text-xs text-amber-950">
              <span className="font-semibold">Advisor note: </span>
              {announcement.rejectionReason}
            </p>
          ) : null}
        </div>
      </div>

      <div className="mt-2">
        <p
          className={`text-sm leading-relaxed text-slate-600 ${
            !bodyExpanded && expandableBody ? "line-clamp-3" : ""
          }`}
        >
          {announcement.content}
        </p>
        {expandableBody ? (
          <button
            type="button"
            onClick={() => setBodyExpanded(!bodyExpanded)}
            className="mt-1.5 text-xs font-semibold text-slate-700 underline decoration-slate-300 underline-offset-2 hover:text-slate-900"
          >
            {bodyExpanded ? "Show less" : "Read more"}
          </button>
        ) : null}
      </div>

      {announcement.attachments && announcement.attachments.length > 0 ? (
        <div className="mt-3 sm:mt-4">
          {(() => {
            const images = announcement.attachments.filter((a) => isImageMime(a.fileType));
            const files = announcement.attachments.filter((a) => !isImageMime(a.fileType));
            return (
              <>
                {images.length > 0 ? (
                  <ul className="-mx-1 flex max-sm:snap-x max-sm:snap-mandatory gap-3 overflow-x-auto pb-2 sm:mx-0 sm:flex-wrap sm:overflow-visible sm:pb-0">
                    {images.map((att) => (
                      <li
                        key={att.id}
                        className="w-[min(100%,280px)] max-sm:snap-center max-sm:shrink-0 sm:w-auto sm:max-w-md sm:shrink"
                      >
                        <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-1.5 sm:p-2">
                          <a
                            href={att.signedUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="block overflow-hidden rounded-md"
                          >
                            {/* eslint-disable-next-line @next/next/no-img-element -- signed Supabase URL */}
                            <img
                              src={att.signedUrl}
                              alt={att.fileName}
                              className="h-40 w-full object-cover sm:h-auto sm:max-h-52 sm:object-contain"
                            />
                          </a>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : null}
                {files.length > 0 ? (
                  <ul className="mt-2 flex flex-col gap-2">
                    {files.map((att) => (
                      <li key={att.id} className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2">
                        <a
                          href={att.signedUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm font-medium text-slate-800 underline decoration-slate-300 underline-offset-2 hover:text-slate-950"
                        >
                          Download {att.fileName}
                        </a>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </>
            );
          })()}
        </div>
      ) : null}

      {hasPoll && announcement.pollOptions ? (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/90 p-3 sm:p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Poll</p>
          <p className="mt-1 text-sm font-semibold text-slate-900">{announcement.pollQuestion}</p>
          {!hasVoted ? (
            <div className="mt-3 flex flex-col gap-2">
              {announcement.pollOptions.map((label, idx) => (
                <button
                  key={idx}
                  type="button"
                  disabled={pending}
                  onClick={() => vote(idx)}
                  className="rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-left text-sm font-medium text-slate-800 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 disabled:opacity-60"
                >
                  {label}
                </button>
              ))}
            </div>
          ) : (
            <div className="mt-3 space-y-2">
              {announcement.pollOptions.map((label, idx) => {
                const row = pollTallies.find((t) => t.optionIndex === idx);
                const c = row?.count ?? 0;
                const pct = totalVotes > 0 ? Math.round((c / totalVotes) * 100) : 0;
                const isMine = localVoteIndex === idx;
                return (
                  <div key={idx}>
                    <div className="flex items-center justify-between gap-2 text-xs font-medium text-slate-700">
                      <span className={isMine ? "text-slate-950" : ""}>
                        {label}
                        {isMine ? " · Your vote" : ""}
                      </span>
                      <span className="tabular-nums text-slate-500">
                        {c} ({pct}%)
                      </span>
                    </div>
                    <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-200">
                      <div
                        className={`h-full rounded-full ${isMine ? "bg-slate-900" : "bg-slate-500"}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
              <p className="pt-1 text-xs text-slate-500">{totalVotes} total votes</p>
            </div>
          )}
        </div>
      ) : null}

      {showReadRow ? (
        <div className="mt-3 border-t border-slate-100 pt-3">
          <button
            type="button"
            onClick={toggleReadStats}
            className="flex w-full items-center justify-between gap-2 text-left text-xs font-medium text-slate-600"
            aria-expanded={readStatsOpen}
          >
            <span>
              Seen by {readCount} / {totalMembers} members
            </span>
            <span className="shrink-0 text-slate-400" aria-hidden>
              {readStatsOpen ? "▲" : "▼"}
            </span>
          </button>

          {readStatsOpen ? (
            <div className="mt-2 rounded-lg border border-slate-200 bg-white p-3 text-sm shadow-sm">
              {!canOpenReadersList ? (
                <p className="text-xs text-slate-600">
                  {readCount === 0
                    ? "No members have opened this post in the app yet."
                    : `${readCount} of ${totalMembers} members have opened this update.`}
                </p>
              ) : readersLoading ? (
                <p className="text-xs text-slate-500">Loading…</p>
              ) : readers && readers.length > 0 ? (
                <>
                  <p className="text-xs font-semibold text-slate-800">Who read this</p>
                  <ul className="mt-2 max-h-48 space-y-1.5 overflow-y-auto text-xs text-slate-700">
                    {readers.map((r) => (
                      <li
                        key={r.userId}
                        className="flex justify-between gap-2 border-b border-slate-100 pb-1.5 last:border-0"
                      >
                        <span className="min-w-0 truncate">{r.fullName || r.email || "Member"}</span>
                        <span className="flex-shrink-0 text-slate-400">
                          {new Date(r.readAt).toLocaleString(undefined, {
                            month: "short",
                            day: "numeric",
                            hour: "numeric",
                            minute: "2-digit",
                          })}
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              ) : readCount > 0 ? (
                <p className="text-xs text-slate-500">Could not load the reader list.</p>
              ) : (
                <p className="text-xs text-slate-500">No reads recorded yet.</p>
              )}
            </div>
          ) : null}
        </div>
      ) : null}

      {canManageAnnouncement ? (
        <AnnouncementManagementControls
          clubId={clubId}
          announcementId={announcement.id}
          title={announcement.title}
          content={announcement.content}
          isPublished={announcement.isPublished}
          isPinned={announcement.isPinned}
          isUrgent={announcement.isUrgent}
          canEdit={canEditAnnouncement}
          canDelete={canDeleteAnnouncement}
        />
      ) : null}
    </article>
  );
}
