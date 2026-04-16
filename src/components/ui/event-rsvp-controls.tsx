"use client";

import { useFormStatus } from "react-dom";
import { upsertRsvpAction } from "@/app/(app)/clubs/actions";

type RsvpStatus = "yes" | "maybe" | "no" | "waitlist";

type EventRsvpControlsProps = {
  clubId: string;
  eventId: string;
  selectedStatus: RsvpStatus | null;
  recentlySaved: boolean;
  /** Omit duplicate heading when the parent card already introduces RSVP (cleaner hierarchy). */
  embedded?: boolean;
};

const RSVP_OPTIONS: Array<{
  status: RsvpStatus;
  label: string;
  tone: string;
}> = [
  { status: "yes", label: "Yes", tone: "rsvp-option-yes" },
  { status: "maybe", label: "Maybe", tone: "rsvp-option-maybe" },
  { status: "no", label: "No", tone: "rsvp-option-no" },
];

function SubmitButton({
  status,
  label,
  tone,
  selectedStatus,
}: {
  status: RsvpStatus;
  label: string;
  tone: string;
  selectedStatus: RsvpStatus | null;
}) {
  const { pending } = useFormStatus();
  const isSelected = selectedStatus === status;

  return (
    <button
      type="submit"
      name="status"
      value={status}
      disabled={pending}
      aria-pressed={isSelected}
      className={`rsvp-option ${tone} ${isSelected ? "is-selected" : ""} ${pending ? "is-pending" : ""}`}
    >
      <span className="rsvp-option-label">{label}</span>
      <span className="rsvp-option-state">{isSelected ? "Selected" : "Choose"}</span>
    </button>
  );
}

export function EventRsvpControls({
  clubId,
  eventId,
  selectedStatus,
  recentlySaved,
  embedded = false,
}: EventRsvpControlsProps) {
  const savedLabel = selectedStatus === "waitlist"
    ? "Waitlisted"
    : selectedStatus
      ? `${selectedStatus.toUpperCase()} saved`
      : "Response saved";

  return (
    <form
      action={upsertRsvpAction}
      className={
        embedded
          ? "event-action-panel event-action-panel-embedded"
          : "event-action-panel"
      }
    >
      <input type="hidden" name="club_id" value={clubId} />
      <input type="hidden" name="event_id" value={eventId} />
      {embedded ? (
        recentlySaved ? (
          <p className="mb-3">
            <span className="feedback-pill feedback-pill-success">{savedLabel}</span>
          </p>
        ) : null
      ) : (
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-slate-900">Your RSVP</p>
            <p className="mt-1 text-sm text-slate-600">Pick the response that best matches your plan.</p>
          </div>
          {recentlySaved ? <span className="feedback-pill feedback-pill-success">{savedLabel}</span> : null}
        </div>
      )}
      <div className={`rsvp-segmented-control ${embedded ? "mt-0" : "mt-4"}`}>
        {RSVP_OPTIONS.map((option) => (
          <SubmitButton
            key={option.status}
            status={option.status}
            label={option.label}
            tone={option.tone}
            selectedStatus={selectedStatus}
          />
        ))}
      </div>
    </form>
  );
}
