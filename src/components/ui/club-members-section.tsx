import { removeMemberAction, updateMemberRoleAction } from "@/app/(app)/clubs/actions";
import { GettingStartedChecklist } from "@/components/ui/getting-started-checklist";
import { MemberInvite } from "@/components/ui/member-invite";
import type { ClubDetail } from "@/lib/clubs/queries";
import { getMemberDisplayName, getMemberInitials, getMemberSecondaryText } from "@/lib/member-display";

type ClubMembersSectionProps = {
  club: ClubDetail;
  query: {
    memberError?: string;
    memberSuccess?: string;
  };
};

export function ClubMembersSection({ club, query }: ClubMembersSectionProps) {
  const memberCount = club.memberCount;
  const officerCount = club.members.filter((m) => m.role === "officer").length;
  const regularMemberCount = memberCount - officerCount;
  const setupDone = memberCount > 1 && club.announcements.length > 0 && club.events.length > 0;

  return (
    <section className="space-y-6">

      {/* Page header */}
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-indigo-50 p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">People</p>
          <h1 className="section-title mt-3 text-3xl md:text-4xl">Members</h1>
          <p className="section-subtitle mt-4 max-w-2xl text-lg text-slate-700">
            {club.currentUserRole === "officer"
              ? "Manage who is in this club, review attendance history, and invite new members."
              : "See who is part of this club and how everyone is doing."}
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-8">
            <div>
              <p className="text-2xl font-bold text-slate-900">{memberCount}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {memberCount === 1 ? "Member" : "Members"}
              </p>
            </div>

            <div className="h-8 w-px bg-slate-200" />

            <div>
              <p className="text-2xl font-bold text-slate-900">{officerCount}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {officerCount === 1 ? "Officer" : "Officers"}
              </p>
            </div>

            {club.totalTrackedEvents > 0 && (
              <>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-2xl font-bold text-slate-900">{club.clubAverageAttendance}%</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Avg. Attendance</p>
                </div>
              </>
            )}
          </div>

          {club.currentUserRole === "officer" && (
            <div className="mt-8">
              <a href="#invite-members" className="btn-primary px-6 py-3 text-base font-semibold">
                Invite Members
              </a>
            </div>
          )}
        </div>
      </header>

      {/* Invite tools — officer only */}
      {club.currentUserRole === "officer" && (
        <section id="invite-members">
          <MemberInvite joinCode={club.joinCode} membersCount={memberCount} />
        </section>
      )}

      {/* Getting started — officer only, hidden once all steps are done */}
      {club.currentUserRole === "officer" && !setupDone && (
        <GettingStartedChecklist
          clubId={club.id}
          membersCount={memberCount}
          announcementsCount={club.announcements.length}
          eventsCount={club.events.length}
        />
      )}

      {/* Member roster */}
      <div className="card-surface p-5" id="members">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Roster</p>
            <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">All Members</h2>
            <p className="mt-1 text-sm text-slate-600">
              {officerCount} {officerCount === 1 ? "officer" : "officers"}
              {regularMemberCount > 0
                ? ` · ${regularMemberCount} ${regularMemberCount === 1 ? "member" : "members"}`
                : null}
              {club.currentUserRole === "officer" ? " — officers are listed first" : null}
            </p>
          </div>
          <span className="badge-soft">{memberCount} total</span>
        </div>

        {query.memberSuccess ? <p className="alert-success mt-4">{query.memberSuccess}</p> : null}
        {query.memberError ? <p className="alert-error mt-3">{query.memberError}</p> : null}

        {memberCount === 0 ? (
          <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-8 text-center">
            <p className="font-semibold text-slate-900">No members yet</p>
            <p className="mt-1 text-sm text-slate-500">
              {club.currentUserRole === "officer"
                ? "Share your join code above to invite people."
                : "You're the first one here."}
            </p>
          </div>
        ) : (
          <ul className="list-stack mt-4">
            {club.members.map((member) => {
              const isCurrentUser = member.userId === club.currentUserId;
              const isOfficer = member.role === "officer";
              const canManage = club.currentUserRole === "officer" && !isCurrentUser;

              return (
                <li
                  key={member.userId}
                  className={`member-card ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}
                >
                  {/* Identity row */}
                  <div className="flex items-start gap-3">
                    <div className={`member-avatar ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}>
                      {getMemberInitials(member)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-base font-semibold tracking-tight text-slate-950">
                          {getMemberDisplayName(member)}
                        </p>
                        <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>
                          {member.role}
                        </span>
                        {isCurrentUser ? <span className="member-you-pill">You</span> : null}
                      </div>
                      <p className="mt-1 truncate text-sm text-slate-500">{getMemberSecondaryText(member)}</p>
                    </div>
                  </div>

                  {/* Attendance */}
                  <div className="mt-3 pl-14">
                    {member.totalTrackedEvents > 0 ? (
                      <div>
                        <div className="mb-1.5 flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">Attendance</span>
                          <span className="text-xs font-semibold text-slate-600">
                            {member.attendanceCount}/{member.totalTrackedEvents} events · {member.attendanceRate}%
                          </span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-slate-100">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-emerald-500 transition-[width] duration-300"
                            style={{ width: `${member.attendanceRate}%` }}
                          />
                        </div>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-400">No tracked events yet</p>
                    )}
                  </div>

                  {/* Officer management actions */}
                  {canManage ? (
                    <div className="member-card-actions">
                      {member.role === "member" ? (
                        <form action={updateMemberRoleAction}>
                          <input type="hidden" name="club_id" value={club.id} />
                          <input type="hidden" name="user_id" value={member.userId} />
                          <input type="hidden" name="role" value="officer" />
                          <button type="submit" className="btn-secondary text-xs">
                            Promote to Officer
                          </button>
                        </form>
                      ) : (
                        <form action={updateMemberRoleAction}>
                          <input type="hidden" name="club_id" value={club.id} />
                          <input type="hidden" name="user_id" value={member.userId} />
                          <input type="hidden" name="role" value="member" />
                          <button type="submit" className="btn-secondary text-xs">
                            Demote to Member
                          </button>
                        </form>
                      )}
                      <form action={removeMemberAction}>
                        <input type="hidden" name="club_id" value={club.id} />
                        <input type="hidden" name="user_id" value={member.userId} />
                        <button type="submit" className="btn-danger text-xs">
                          Remove from Club
                        </button>
                      </form>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </div>

    </section>
  );
}
