"use client";

import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  getAnnouncementReadersAction,
  markAnnouncementReadAction,
  votePollAnnouncementAction,
  type AnnouncementReaderRow,
} from "@/app/(app)/clubs/announcement-communication-actions";
import type { ClubAnnouncement } from "@/lib/clubs/queries";

type AnnouncementFeedItemProps = {
  announcement: ClubAnnouncement;
  /** Officers or members with announcements.edit may open the reader list. */
  canOpenReadersList: boolean;
  variant: "featured" | "compact";
};

function isImageMime(mime: string): boolean {
  return mime.startsWith("image/");
}

export function AnnouncementFeedItem({
  announcement,
  canOpenReadersList,
  variant,
}: AnnouncementFeedItemProps) {
  const router = useRouter();
  const rootRef = useRef<HTMLElement | null>(null);
  const markedRef = useRef(false);
  const [readersOpen, setReadersOpen] = useState(false);
  const [readers, setReaders] = useState<AnnouncementReaderRow[] | null>(null);
  const [readersLoading, setReadersLoading] = useState(false);
  const [pending, startTransition] = useTransition();
  const [localVoteIndex, setLocalVoteIndex] = useState<number | null>(announcement.userPollVoteIndex ?? null);

  useEffect(() => {
    setLocalVoteIndex(announcement.userPollVoteIndex ?? null);
  }, [announcement.id, announcement.userPollVoteIndex]);

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

  async function openReaders() {
    if (!canOpenReadersList) return;
    setReadersOpen(true);
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

  const pollTallies = announcement.pollTallies ?? [];
  const totalVotes = announcement.totalPollVotes ?? 0;
  const hasVoted = localVoteIndex !== null;

  function vote(idx: number) {
    startTransition(async () => {
      const res = await votePollAnnouncementAction(announcement.id, idx);
      if (res.ok) {
        setLocalVoteIndex(idx);
        router.refresh();
      }
    });
  }

  const scheduledLabel =
    announcement.scheduledFor && !announcement.isPublished
      ? `Scheduled · ${new Date(announcement.scheduledFor).toLocaleString()}`
      : null;

  const articleClass =
    variant === "featured" ? "ann-latest-card" : "sm:surface-subcard sm:p-4 sm:py-4 py-3 first:pt-0 last:pb-0";

  return (
    <article ref={rootRef} id={`announcement-${announcement.id}`} className={articleClass}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            {variant === "featured" ? (
              <span className="feedback-pill feedback-pill-fresh">Latest</span>
            ) : null}
            {scheduledLabel ? (
              <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-800">
                {scheduledLabel}
              </span>
            ) : null}
            <span className="text-xs text-slate-400">{announcement.createdAt}</span>
          </div>
          <h3
            className={
              variant === "featured"
                ? "mt-2 text-lg font-bold tracking-tight text-slate-900 sm:mt-3 sm:text-xl"
                : "text-sm font-semibold text-slate-900"
            }
          >
            {announcement.title}
          </h3>
        </div>
      </div>

      <p
        className={
          variant === "featured"
            ? "mt-3 text-sm leading-relaxed text-slate-600 sm:mt-4 sm:leading-7"
            : "mt-1.5 line-clamp-3 text-xs leading-relaxed text-slate-600 sm:mt-2 sm:line-clamp-none sm:text-sm sm:leading-6"
        }
      >
        {announcement.content}
      </p>

      {announcement.attachments && announcement.attachments.length > 0 ? (
        <ul className="mt-3 flex flex-col gap-2 sm:mt-4">
          {announcement.attachments.map((att) => (
            <li key={att.id} className="rounded-lg border border-slate-200 bg-slate-50/80 p-2">
              {isImageMime(att.fileType) ? (
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
                    className="h-auto max-h-64 w-full object-contain"
                  />
                </a>
              ) : (
                <a
                  href={att.signedUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm font-medium text-slate-800 underline decoration-slate-300 underline-offset-2 hover:text-slate-950"
                >
                  Download {att.fileName}
                </a>
              )}
            </li>
          ))}
        </ul>
      ) : null}

      {hasPoll && announcement.pollOptions ? (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/90 p-3 sm:p-4">
          <p className="text-sm font-semibold text-slate-900">{announcement.pollQuestion}</p>
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

      {announcement.isPublished ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <span>
            Seen by {readCount} / {totalMembers} members
          </span>
          {canOpenReadersList && readCount > 0 ? (
            <>
              <span aria-hidden>·</span>
              <button
                type="button"
                onClick={openReaders}
                className="font-semibold text-slate-700 underline decoration-slate-300 underline-offset-2 hover:text-slate-900"
              >
                Who read this?
              </button>
            </>
          ) : null}
        </div>
      ) : null}

      {readersOpen ? (
        <div className="mt-3 rounded-lg border border-slate-200 bg-white p-3 text-sm shadow-sm">
          <div className="flex items-center justify-between gap-2">
            <p className="font-semibold text-slate-900">Read receipt</p>
            <button
              type="button"
              onClick={() => setReadersOpen(false)}
              className="text-xs font-medium text-slate-500 hover:text-slate-800"
            >
              Close
            </button>
          </div>
          {readersLoading ? (
            <p className="mt-2 text-xs text-slate-500">Loading…</p>
          ) : readers && readers.length > 0 ? (
            <ul className="mt-2 max-h-48 space-y-1.5 overflow-y-auto text-xs text-slate-700">
              {readers.map((r) => (
                <li key={r.userId} className="flex justify-between gap-2 border-b border-slate-100 pb-1.5 last:border-0">
                  <span className="min-w-0 truncate">{r.fullName || r.email || "Member"}</span>
                  <span className="flex-shrink-0 text-slate-400">
                    {new Date(r.readAt).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-xs text-slate-500">No reads recorded yet.</p>
          )}
        </div>
      ) : null}
    </article>
  );
}
