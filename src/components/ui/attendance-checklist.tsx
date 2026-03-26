"use client";

import { toggleAttendanceAction } from "@/app/(app)/clubs/actions";
import type { ClubMember } from "@/lib/clubs/queries";
import { getMemberDisplayName, getMemberSecondaryText } from "@/lib/member-display";

type AttendanceChecklistProps = {
  clubId: string;
  eventId: string;
  members: ClubMember[];
  presentMemberIds: string[];
};

export function AttendanceChecklist({
  clubId,
  eventId,
  members,
  presentMemberIds,
}: AttendanceChecklistProps) {
  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const form = event.currentTarget.form;
    if (!form) {
      return;
    }

    const presentInput = form.querySelector('input[name="present"]') as HTMLInputElement | null;
    if (presentInput) {
      presentInput.value = event.currentTarget.checked ? "true" : "false";
    }

    form.requestSubmit();
  };

  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/80 p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-900">Attendance</p>
          <p className="mt-1 text-sm text-slate-600">Check off members as they arrive.</p>
        </div>
        <span className="badge-soft">{presentMemberIds.length} present</span>
      </div>
      <ul className="mt-4 space-y-2">
        {members.map((member) => {
          const isPresent = presentMemberIds.includes(member.userId);
          const displayName = getMemberDisplayName(member);

          return (
            <li key={member.userId}>
              <form action={toggleAttendanceAction} className="rounded-lg border border-slate-200 bg-white px-3 py-2">
                <input type="hidden" name="club_id" value={clubId} />
                <input type="hidden" name="event_id" value={eventId} />
                <input type="hidden" name="user_id" value={member.userId} />
                <input type="hidden" name="present" value={isPresent ? "true" : "false"} />
                <label className="flex cursor-pointer items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-900">{displayName}</p>
                    <p className="truncate text-xs text-slate-500">{getMemberSecondaryText(member)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-medium ${isPresent ? "text-emerald-700" : "text-slate-500"}`}>
                      {isPresent ? "Present" : "Not marked"}
                    </span>
                    <input
                      type="checkbox"
                      defaultChecked={isPresent}
                      onChange={handleChange}
                      className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-500"
                    />
                  </div>
                </label>
              </form>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
