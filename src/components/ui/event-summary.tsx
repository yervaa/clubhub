import Link from "next/link";
import type { ReactNode } from "react";
import { formatEventDateMedium, formatEventTimeShort, parseEventInstant } from "@/lib/events/format-event-display";

function CalendarIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
    </svg>
  );
}

function MapPinIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
      <path d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

export type EventMetaRowProps = {
  at: Date | string;
  location?: string | null;
  /** Hide time segment (e.g. date-only feed lines). */
  dateOnly?: boolean;
  /** Tighter icon + text for dense rows. */
  compact?: boolean;
  className?: string;
};

/**
 * Single grouped row: calendar + date · time, then pin + location (when present).
 */
export function EventMetaRow({ at, location, dateOnly = false, compact = false, className = "" }: EventMetaRowProps) {
  const d = parseEventInstant(at);
  const dateStr = formatEventDateMedium(d);
  const timeStr = dateOnly ? null : formatEventTimeShort(d);
  const loc = location?.trim();

  const iconClass = compact ? "event-meta-row-icon h-3.5 w-3.5" : "event-meta-row-icon h-4 w-4";
  const textClass = compact ? "text-[13px] leading-snug sm:text-sm" : "text-sm leading-snug";

  return (
    <div className={`event-meta-row ${textClass} ${className}`.trim()}>
      <span className="event-meta-row-cluster inline-flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
        <CalendarIcon className={iconClass} />
        <span className="font-medium text-slate-700">{dateStr}</span>
        {timeStr ? (
          <>
            <span className="text-slate-300" aria-hidden>
              ·
            </span>
            <span className="text-slate-600">{timeStr}</span>
          </>
        ) : null}
      </span>
      {loc ? (
        <>
          <span className="event-meta-row-sep text-slate-200" aria-hidden>
            |
          </span>
          <span className="event-meta-row-cluster inline-flex min-w-0 max-w-full items-start gap-x-1.5 text-slate-600">
            <MapPinIcon className={`${iconClass} mt-0.5 shrink-0`} />
            <span className="min-w-0 break-words">{loc}</span>
          </span>
        </>
      ) : null}
    </div>
  );
}

export type EventSummaryBlockProps = {
  title: string;
  /** `h3` on full cards, `p` inside links to avoid heading stacks */
  titleAs?: "h2" | "h3" | "p";
  titleSize?: "list" | "panel" | "hero";
  titleAside?: ReactNode;
  secondaryLine?: ReactNode;
  at: Date | string;
  location?: string | null;
  metaDateOnly?: boolean;
  metaCompact?: boolean;
  description?: string | null;
  descriptionClamp?: number;
  supporting?: ReactNode;
  /** Add top border before supporting row */
  supportingBorder?: boolean;
  className?: string;
};

const titleSizeClass: Record<NonNullable<EventSummaryBlockProps["titleSize"]>, string> = {
  list: "text-base font-semibold leading-snug tracking-tight text-slate-950",
  panel: "text-lg font-semibold leading-snug tracking-tight text-slate-950 sm:text-xl",
  hero: "text-xl font-semibold leading-snug tracking-tight text-slate-950 sm:text-2xl",
};

export function EventSummaryBlock({
  title,
  titleAs = "p",
  titleSize = "list",
  titleAside,
  secondaryLine,
  at,
  location,
  metaDateOnly = false,
  metaCompact = false,
  description,
  descriptionClamp = 2,
  supporting,
  supportingBorder = true,
  className = "",
}: EventSummaryBlockProps) {
  const TitleTag = titleAs;

  return (
    <div className={`event-summary-block space-y-2 ${className}`.trim()}>
      <div className="flex items-start justify-between gap-3">
        <TitleTag className={`min-w-0 ${titleSizeClass[titleSize]}`}>{title}</TitleTag>
        {titleAside ? <div className="flex shrink-0 flex-wrap justify-end gap-1.5">{titleAside}</div> : null}
      </div>
      {secondaryLine ? (
        <div className="text-xs leading-relaxed text-slate-500 sm:text-[13px]">{secondaryLine}</div>
      ) : null}
      <EventMetaRow at={at} location={location} dateOnly={metaDateOnly} compact={metaCompact} />
      {description ? (
        <p
          className={`text-sm leading-relaxed text-slate-600 ${
            descriptionClamp === 2 ? "line-clamp-2" : descriptionClamp === 3 ? "line-clamp-3" : ""
          }`}
        >
          {description}
        </p>
      ) : null}
      {supporting ? (
        <div
          className={`text-xs leading-relaxed text-slate-500 ${supportingBorder ? "border-t border-slate-100 pt-2.5" : "pt-0.5"}`}
        >
          {supporting}
        </div>
      ) : null}
    </div>
  );
}

export type EventSummaryListLinkProps = {
  href: string;
  title: string;
  clubName?: string;
  eventType?: string;
  at: Date | string;
  location?: string | null;
  titleAside?: ReactNode;
  supporting?: ReactNode;
  className?: string;
};

/** Dashboard / cross-club list: title + badges row, club · type, meta, optional supporting */
export function EventSummaryListLink({
  href,
  title,
  clubName,
  eventType,
  at,
  location,
  titleAside,
  supporting,
  className = "",
}: EventSummaryListLinkProps) {
  const secondary = [clubName, eventType].filter(Boolean).join(" · ");

  return (
    <Link
      href={href}
      className={`event-summary-list-link group block ${className}`.trim()}
    >
      <EventSummaryBlock
        title={title}
        titleAs="p"
        titleSize="list"
        titleAside={titleAside}
        secondaryLine={secondary || undefined}
        at={at}
        location={location}
        supporting={supporting}
        supportingBorder={Boolean(supporting)}
        metaCompact
      />
    </Link>
  );
}

/** “Soon” / relative chip for dashboard lists */
export function eventSoonBadge(hoursUntil: number) {
  if (hoursUntil > 48 || hoursUntil <= 0) return null;
  return (
    <span className="rounded-md bg-orange-100 px-2 py-0.5 text-[11px] font-semibold text-orange-900 ring-1 ring-orange-200/80">
      Soon
    </span>
  );
}

/** Lifecycle chips for full event cards (attached to title row) */
export function eventLifecycleBadges(options: {
  isPast: boolean;
  isToday: boolean;
  isComingSoon: boolean;
  hasReflection: boolean;
}) {
  const { isPast, isToday, isComingSoon, hasReflection } = options;
  const chips: ReactNode[] = [];

  if (isPast) {
    chips.push(
      <span
        key="done"
        className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-700 ring-1 ring-slate-200/90"
      >
        Completed
      </span>,
    );
  } else if (isToday) {
    chips.push(
      <span
        key="today"
        className="rounded-md bg-blue-100 px-2 py-0.5 text-[11px] font-semibold text-blue-900 ring-1 ring-blue-200/80"
      >
        Today
      </span>,
    );
  } else if (isComingSoon) {
    chips.push(
      <span
        key="soon"
        className="rounded-md bg-orange-100 px-2 py-0.5 text-[11px] font-semibold text-orange-900 ring-1 ring-orange-200/80"
      >
        Soon
      </span>,
    );
  } else {
    chips.push(
      <span
        key="up"
        className="rounded-md bg-slate-50 px-2 py-0.5 text-[11px] font-semibold text-slate-600 ring-1 ring-slate-200/80"
      >
        Upcoming
      </span>,
    );
  }

  if (isPast && hasReflection) {
    chips.push(
      <span
        key="refl"
        className="rounded-md bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-800 ring-1 ring-emerald-200/80"
      >
        Reflection
      </span>,
    );
  }

  return <>{chips}</>;
}

/** Event advisor workflow (organizers/advisors only — members do not receive non-approved rows from RLS). */
export function eventApprovalStatusAside(approvalStatus: "approved" | "pending" | "rejected") {
  if (approvalStatus === "approved") return null;
  if (approvalStatus === "pending") {
    return (
      <span className="rounded-md bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-900 ring-1 ring-violet-200/80">
        Pending approval
      </span>
    );
  }
  return (
    <span className="rounded-md bg-rose-100 px-2 py-0.5 text-[11px] font-semibold text-rose-900 ring-1 ring-rose-200/80">
      Not approved
    </span>
  );
}

export function eventPastFoldableBadges(hasReflection: boolean) {
  return (
    <>
      <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-700 ring-1 ring-slate-200/90">
        Past
      </span>
      {hasReflection ? (
        <span className="rounded-md bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-800 ring-1 ring-emerald-200/80">
          Reflection
        </span>
      ) : (
        <span className="rounded-md bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-900 ring-1 ring-amber-200/70">
          No reflection
        </span>
      )}
    </>
  );
}

export type ContentSummaryListLinkProps = {
  href: string;
  title: string;
  secondaryLine?: ReactNode;
  timestamp: Date | string;
  showTime?: boolean;
  titleAside?: ReactNode;
};

/** Announcements and other feed rows — same hierarchy as events */
export function ContentSummaryListLink({
  href,
  title,
  secondaryLine,
  timestamp,
  showTime = true,
  titleAside,
}: ContentSummaryListLinkProps) {
  return (
    <Link href={href} className="event-summary-list-link group block">
      <EventSummaryBlock
        title={title}
        titleAs="p"
        titleSize="list"
        titleAside={titleAside}
        secondaryLine={secondaryLine}
        at={timestamp}
        metaDateOnly={!showTime}
        supporting={undefined}
        metaCompact
      />
    </Link>
  );
}
