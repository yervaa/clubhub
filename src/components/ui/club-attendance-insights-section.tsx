import type { ClubDetail } from "@/lib/clubs/queries";
import { getMemberDisplayName, getMemberInitials } from "@/lib/member-display";

type ClubAttendanceInsightsSectionProps = {
  club: ClubDetail;
};

export function ClubAttendanceInsightsSection({ club }: ClubAttendanceInsightsSectionProps) {
  return (
    <div className="card-surface p-5" id="attendance-insights">
      <div className="section-card-header">
        <div>
          <p className="section-kicker">Insights</p>
          <h3 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Attendance Insights</h3>
          <p className="mt-1 text-sm text-slate-600">
            Based only on past events where attendance was marked for at least one member.
          </p>
        </div>
        <span className="badge-soft">{club.totalTrackedEvents} tracked</span>
      </div>

      {club.totalTrackedEvents === 0 ? (
        <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-emerald-50 to-slate-50 p-6">
          <p className="font-semibold text-slate-900">No attendance insights yet</p>
          <p className="mt-1 text-sm text-slate-600">
            Mark attendance at a past or current event to start building attendance trends for the club.
          </p>
        </div>
      ) : (
        <div className="mt-4 grid gap-4 lg:grid-cols-[0.95fr,1.45fr]">
          <div className="surface-subcard p-4">
            <p className="stat-label">Club average attendance</p>
            <p className="stat-value">{club.clubAverageAttendance}%</p>
            <p className="stat-copy">
              Average member attendance rate across {club.totalTrackedEvents} tracked {club.totalTrackedEvents === 1 ? "event" : "events"}.
            </p>
          </div>

          <div className="surface-subcard p-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="stat-label">Most active members</p>
                <p className="mt-2 text-sm text-slate-600">Top 3 by attendance percentage.</p>
              </div>
              <span className="badge-soft">{club.topMembers.length} shown</span>
            </div>
            <ul className="list-stack mt-4">
              {club.topMembers.map((member, index) => (
                <li key={member.userId} className="surface-subcard p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0 flex items-center gap-3">
                      <div
                        className={`member-avatar ${member.role === "officer" ? "is-officer" : ""} ${member.userId === club.currentUserId ? "is-current-user" : ""}`}
                      >
                        {getMemberInitials(member)}
                      </div>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="truncate text-sm font-semibold text-slate-900">
                            {index + 1}. {getMemberDisplayName(member)}
                          </p>
                          <span className={`member-role-pill ${member.role === "officer" ? "is-officer" : "is-member"}`}>
                            {member.role}
                          </span>
                          {member.userId === club.currentUserId ? <span className="member-you-pill">You</span> : null}
                        </div>
                        <p className="mt-1 truncate text-sm text-slate-600">
                          Attendance: {member.attendanceCount} / {member.totalTrackedEvents} ({member.attendanceRate}%)
                        </p>
                      </div>
                    </div>
                    <div className="rounded-full bg-slate-100 px-3 py-1.5 text-sm font-semibold text-slate-900">
                      {member.attendanceRate}%
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
