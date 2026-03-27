"use client";

import type { ClubMember } from "@/lib/clubs/queries";
import { AttendanceToggleRow } from "@/components/ui/attendance-toggle-row";

type AttendanceChecklistProps = {
  clubId: string;
  eventId: string;
  members: ClubMember[];
  presentMemberIds: string[];
  currentUserId: string;
  recentlySavedUserId?: string;
  recentlySavedPresent?: boolean;
};

export function AttendanceChecklist({
  clubId,
  eventId,
  members,
  presentMemberIds,
  currentUserId,
  recentlySavedUserId,
  recentlySavedPresent,
}: AttendanceChecklistProps) {
  const respondedCount = presentMemberIds.length;
  const pendingCount = Math.max(members.length - respondedCount, 0);

  return (
    <div className="mt-5 rounded-2xl border border-slate-200 bg-linear-to-br from-white to-slate-50 p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-900">Attendance</p>
          <p className="mt-1 text-sm text-slate-600">Mark members as they arrive with a clear present or not present state.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="badge-soft">{respondedCount} present</span>
          <span className="badge-soft">{pendingCount} unmarked</span>
          {recentlySavedUserId ? <span className="feedback-pill feedback-pill-success">Attendance saved</span> : null}
        </div>
      </div>
      <ul className="mt-4 space-y-2.5">
        {members.map((member) => {
          const isPresent = presentMemberIds.includes(member.userId);

          return (
            <AttendanceToggleRow
              key={member.userId}
              clubId={clubId}
              eventId={eventId}
              member={member}
              isPresent={isPresent}
              isCurrentUser={member.userId === currentUserId}
              recentlySaved={recentlySavedUserId === member.userId && recentlySavedPresent === isPresent}
            />
          );
        })}
      </ul>
    </div>
  );
}
