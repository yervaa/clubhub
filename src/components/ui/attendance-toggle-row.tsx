"use client";

import { useFormStatus } from "react-dom";
import { toggleAttendanceAction } from "@/app/(app)/clubs/actions";
import type { ClubMember } from "@/lib/clubs/queries";
import { getMemberDisplayName, getMemberInitials, getMemberSecondaryText } from "@/lib/member-display";

type AttendanceToggleRowProps = {
  clubId: string;
  eventId: string;
  member: ClubMember;
  isPresent: boolean;
  isCurrentUser: boolean;
  recentlySaved: boolean;
};

function AttendanceButton({
  presentValue,
  label,
  isActive,
  tone,
}: {
  presentValue: "true" | "false";
  label: string;
  isActive: boolean;
  tone: string;
}) {
  const { pending } = useFormStatus();

  return (
    <button
      type="submit"
      name="present"
      value={presentValue}
      disabled={pending}
      aria-pressed={isActive}
      className={`attendance-choice ${tone} ${isActive ? "is-active" : ""} ${pending ? "is-pending" : ""}`}
    >
      {label}
    </button>
  );
}

export function AttendanceToggleRow({
  clubId,
  eventId,
  member,
  isPresent,
  isCurrentUser,
  recentlySaved,
}: AttendanceToggleRowProps) {
  const displayName = getMemberDisplayName(member);
  const secondaryText = getMemberSecondaryText(member);

  return (
    <li>
      <form action={toggleAttendanceAction} className={`attendance-row ${isPresent ? "is-present" : ""}`}>
        <input type="hidden" name="club_id" value={clubId} />
        <input type="hidden" name="event_id" value={eventId} />
        <input type="hidden" name="user_id" value={member.userId} />
        <div className="flex min-w-0 items-center gap-3">
          <div
            className={`member-avatar ${member.role === "officer" ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""} ${isPresent ? "is-present" : ""}`}
          >
            {getMemberInitials(member)}
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <p className="truncate text-sm font-semibold text-slate-900">{displayName}</p>
              <span className={`member-role-pill ${member.role === "officer" ? "is-officer" : "is-member"}`}>
                {member.role}
              </span>
              {isCurrentUser ? <span className="member-you-pill">You</span> : null}
              <span className={`attendance-state-pill ${isPresent ? "is-present" : "is-absent"}`}>
                {isPresent ? "Present" : "Not marked"}
              </span>
              {recentlySaved ? (
                <span className="feedback-pill feedback-pill-success">
                  {isPresent ? "Marked present" : "Marked not present"}
                </span>
              ) : null}
            </div>
            <p className="truncate text-sm text-slate-600">{secondaryText}</p>
          </div>
        </div>
        <div className="attendance-choice-group">
          <AttendanceButton presentValue="true" label="Present" isActive={isPresent} tone="attendance-choice-present" />
          <AttendanceButton presentValue="false" label="Not Present" isActive={!isPresent} tone="attendance-choice-absent" />
        </div>
      </form>
    </li>
  );
}
