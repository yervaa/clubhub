"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useState } from "react";
import { createPortal } from "react-dom";
import { markMemberAlumniAction, removeMemberAction, updateMemberRoleAction } from "@/app/(app)/clubs/actions";
import {
  assignClubCommitteeMemberAction,
  removeClubCommitteeMemberAction,
} from "@/app/(app)/clubs/club-committee-actions";
import {
  assignClubTeamMemberAction,
  removeClubTeamMemberAction,
} from "@/app/(app)/clubs/club-team-actions";
import {
  addClubMemberAvailabilitySlotAction,
  deleteClubMemberAvailabilitySlotAction,
} from "@/app/(app)/clubs/member-availability-actions";
import { setClubMemberDuesAction } from "@/app/(app)/clubs/member-dues-actions";
import { setClubMemberOfficerNoteAction } from "@/app/(app)/clubs/member-officer-notes-actions";
import { MemberProfileContactBlock } from "@/components/ui/member-profile-contact-block";
import {
  addClubMemberSkillInterestAction,
  deleteClubMemberSkillInterestAction,
} from "@/app/(app)/clubs/member-skills-actions";
import {
  assignClubMemberTagAction,
  createClubMemberTagAction,
  deleteClubMemberTagAction,
  removeClubMemberTagAction,
} from "@/app/(app)/clubs/member-tag-actions";
import { formatDuesTermMoneyAndDue, isUnpaidDuesPastDue } from "@/lib/clubs/dues-display";
import type {
  ClubMember,
  ClubCommitteeSummary,
  ClubMemberAttendanceHistoryEntry,
  ClubMemberDuesRecord,
  ClubMemberTag,
  ClubDuesSettings,
  ClubTeamSummary,
} from "@/lib/clubs/queries";
import { formatEventDateMedium, formatEventTimeShort, parseEventInstant } from "@/lib/events/format-event-display";
import { formatAvailabilitySlotLine } from "@/lib/clubs/member-availability-display";
import { buildLeadershipEngagementProfileBlock } from "@/lib/clubs/member-inactivity";
import {
  MEMBER_ENGAGEMENT_SECTION_INTRO,
  PARTICIPATION_SCORE_SUBTITLE,
  TRACKED_ATTENDANCE_SUBTITLE,
  formatTrackedAttendanceSummary,
  trackedAttendanceEmptyCopy,
} from "@/lib/clubs/member-engagement-copy";
import {
  computeParticipationScore,
  PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE,
  participationScoreBand,
} from "@/lib/clubs/participation-score";
import { getMemberRosterDisplayName, getMemberRosterInitials } from "@/lib/member-display";
import { VolunteerHoursPanel } from "@/components/ui/volunteer-hours-panel";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

type MemberProfileDialogProps = {
  open: boolean;
  onClose: () => void;
  member: ClubMember | null;
  clubId: string;
  currentUserId: string;
  rbacRoles: MemberWithRoles["rbacRoles"];
  isPresident: boolean;
  isArchived: boolean;
  canAssignRoles: boolean;
  canRemoveMembers: boolean;
  memberTagDefinitions: ClubMemberTag[];
  canManageMemberTags: boolean;
  clubCommittees: ClubCommitteeSummary[];
  canManageCommittees: boolean;
  clubTeams: ClubTeamSummary[];
  canManageTeams: boolean;
  canManageVolunteerHours: boolean;
  /** Officers / members.manage_member_skills — edit anyone’s skills & interests. */
  canManageMemberSkillsForOthers: boolean;
  /** Officers / members.manage_member_availability — edit anyone’s weekly availability. */
  canManageMemberAvailabilityForOthers: boolean;
  /** Leadership-only internal notes; when false, section is hidden. */
  canManageOfficerNotes: boolean;
  officerNotesByUserId?: Record<string, string>;
  /** Leadership-only dues status; when false, section is hidden and no map is passed from the server. */
  canManageMemberDues: boolean;
  duesByUserId?: Record<string, ClubMemberDuesRecord>;
  /** Club-wide dues term; leadership-only. */
  duesSettings?: ClubDuesSettings | null;
  /**
   * Past events where this member was marked present; server may include only the viewer when they lack
   * `canViewOthersMemberAttendanceHistory`.
   */
  attendanceHistoryByUserId?: Record<string, ClubMemberAttendanceHistoryEntry[]>;
  /**
   * Active officers / `members.view_member_contact` — see others’ optional club phone & preference in profile only.
   */
  canViewMemberContact: boolean;
  /**
   * `insights.view` or active legacy officer — same gate as roster “Likely inactive” / engagement filter.
   */
  canSeeInactiveEngagement?: boolean;
  /**
   * `insights.view` or `attendance.mark` / `attendance.edit` (with legacy officer fallback via `po`) —
   * show per-event attendance history for **other** members. Self always sees own list when data was loaded.
   */
  canViewOthersMemberAttendanceHistory?: boolean;
};

function formatJoinedAt(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function MemberProfileTagsBlock({
  clubId,
  member,
  memberTagDefinitions,
  canManage,
}: {
  clubId: string;
  member: ClubMember;
  memberTagDefinitions: ClubMemberTag[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const tags = member.tags ?? [];
  const assignedIds = new Set(tags.map((t) => t.id));
  const availableToAdd = memberTagDefinitions.filter((t) => !assignedIds.has(t.id));

  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Tags</h3>
      <p className="mt-1 text-xs text-slate-500">Club labels for organizing members — separate from roles.</p>
      {tags.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-2">
          {tags.map((tag) => (
            <li
              key={tag.id}
              className="inline-flex items-center gap-0.5 rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1 text-xs font-semibold text-sky-900"
            >
              <span>{tag.name}</span>
              {canManage ? (
                <button
                  type="button"
                  className="ml-0.5 rounded px-1 text-sky-700 hover:bg-sky-100"
                  aria-label={`Remove ${tag.name}`}
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("tag_id", tag.id);
                    fd.set("user_id", member.userId);
                    setError(null);
                    const r = await removeClubMemberTagAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  ×
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : !canManage ? (
        <p className="mt-2 text-sm text-slate-500">No tags yet.</p>
      ) : null}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage ? (
        <div className="mt-4 space-y-3 border-t border-slate-100 pt-4">
          {availableToAdd.length > 0 ? (
            <form
              className="flex flex-wrap items-end gap-2"
              action={async (fd) => {
                setError(null);
                const r = await assignClubMemberTagAction(fd);
                if (r.ok) router.refresh();
                else setError(r.error);
              }}
            >
              <input type="hidden" name="club_id" value={clubId} />
              <input type="hidden" name="user_id" value={member.userId} />
              <label className="sr-only" htmlFor={`add-tag-${member.userId}`}>
                Add tag
              </label>
              <select
                id={`add-tag-${member.userId}`}
                name="tag_id"
                className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
                defaultValue=""
                required
              >
                <option value="" disabled>
                  Add a tag…
                </option>
                {availableToAdd.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
              <button type="submit" className="btn-secondary text-xs">
                Add
              </button>
            </form>
          ) : null}

          <form
            className="flex flex-wrap items-end gap-2"
            action={async (fd) => {
              setError(null);
              const r = await createClubMemberTagAction(fd);
              if (r.ok) router.refresh();
              else setError(r.error);
            }}
          >
            <input type="hidden" name="club_id" value={clubId} />
            <label className="sr-only" htmlFor={`new-tag-${member.userId}`}>
              New tag name
            </label>
            <input
              id={`new-tag-${member.userId}`}
              name="name"
              placeholder="New tag name"
              className="min-w-[160px] flex-1 rounded-lg border border-slate-200 px-2 py-1.5 text-sm text-slate-900"
              maxLength={40}
              autoComplete="off"
            />
            <button type="submit" className="btn-secondary text-xs">
              Create tag
            </button>
          </form>

          {memberTagDefinitions.length > 0 ? (
            <details className="text-xs text-slate-600">
              <summary className="cursor-pointer font-semibold text-slate-700">Remove tags from club</summary>
              <ul className="mt-2 space-y-1.5">
                {memberTagDefinitions.map((t) => (
                  <li key={t.id} className="flex items-center justify-between gap-2 rounded-lg bg-slate-50 px-2 py-1">
                    <span className="font-medium text-slate-800">{t.name}</span>
                    <button
                      type="button"
                      className="shrink-0 font-semibold text-red-700 hover:underline"
                      onClick={async () => {
                        if (!confirm(`Remove “${t.name}” from this club for all members?`)) return;
                        const fd = new FormData();
                        fd.set("club_id", clubId);
                        fd.set("tag_id", t.id);
                        setError(null);
                        const r = await deleteClubMemberTagAction(fd);
                        if (r.ok) router.refresh();
                        else setError(r.error);
                      }}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function MemberProfileCommitteesBlock({
  clubId,
  member,
  clubCommittees,
  canManage,
}: {
  clubId: string;
  member: ClubMember;
  clubCommittees: ClubCommitteeSummary[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const assigned = member.committees ?? [];
  const assignedIds = new Set(assigned.map((c) => c.id));
  const availableToAdd = clubCommittees.filter((c) => !assignedIds.has(c.id));

  if (clubCommittees.length === 0 && assigned.length === 0 && !canManage) {
    return null;
  }

  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Committees</h3>
      <p className="mt-1 text-xs text-slate-500">
        Club subgroups — create and rename committees from the Members page.
      </p>
      {assigned.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-2">
          {assigned.map((c) => (
            <li
              key={c.id}
              className="inline-flex items-center gap-0.5 rounded-full border border-teal-200 bg-teal-50 px-2.5 py-1 text-xs font-semibold text-teal-900"
            >
              <span>{c.name}</span>
              {canManage ? (
                <button
                  type="button"
                  className="ml-0.5 rounded px-1 text-teal-800 hover:bg-teal-100"
                  aria-label={`Remove ${c.name}`}
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("committee_id", c.id);
                    fd.set("user_id", member.userId);
                    setError(null);
                    const r = await removeClubCommitteeMemberAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  ×
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : !canManage ? (
        <p className="mt-2 text-sm text-slate-500">Not assigned to any committees.</p>
      ) : null}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage && clubCommittees.length === 0 ? (
        <p className="mt-3 text-xs text-slate-500">Create a committee on the Members page to assign this person.</p>
      ) : null}

      {canManage && availableToAdd.length > 0 ? (
        <form
          className="mt-4 flex flex-wrap items-end gap-2 border-t border-slate-100 pt-4"
          action={async (fd) => {
            setError(null);
            const r = await assignClubCommitteeMemberAction(fd);
            if (r.ok) router.refresh();
            else setError(r.error);
          }}
        >
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="user_id" value={member.userId} />
          <label className="sr-only" htmlFor={`add-committee-${member.userId}`}>
            Add to committee
          </label>
          <select
            id={`add-committee-${member.userId}`}
            name="committee_id"
            className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
            defaultValue=""
            required
          >
            <option value="" disabled>
              Add to committee…
            </option>
            {availableToAdd.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <button type="submit" className="btn-secondary text-xs">
            Add
          </button>
        </form>
      ) : null}
    </section>
  );
}

function MemberProfileTeamsBlock({
  clubId,
  member,
  clubTeams,
  canManage,
}: {
  clubId: string;
  member: ClubMember;
  clubTeams: ClubTeamSummary[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const assigned = member.teams ?? [];
  const assignedIds = new Set(assigned.map((t) => t.id));
  const availableToAdd = clubTeams.filter((t) => !assignedIds.has(t.id));

  if (clubTeams.length === 0 && assigned.length === 0 && !canManage) {
    return null;
  }

  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Teams</h3>
      <p className="mt-1 text-xs text-slate-500">
        Distinct from committees — create and rename teams from the Members page.
      </p>
      {assigned.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-2">
          {assigned.map((t) => (
            <li
              key={t.id}
              className="inline-flex items-center gap-0.5 rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1 text-xs font-semibold text-rose-900"
            >
              <span>{t.name}</span>
              {canManage ? (
                <button
                  type="button"
                  className="ml-0.5 rounded px-1 text-rose-800 hover:bg-rose-100"
                  aria-label={`Remove ${t.name}`}
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("team_id", t.id);
                    fd.set("user_id", member.userId);
                    setError(null);
                    const r = await removeClubTeamMemberAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  ×
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : !canManage ? (
        <p className="mt-2 text-sm text-slate-500">Not on any teams.</p>
      ) : null}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage && clubTeams.length === 0 ? (
        <p className="mt-3 text-xs text-slate-500">Create a team on the Members page to assign this person.</p>
      ) : null}

      {canManage && availableToAdd.length > 0 ? (
        <form
          className="mt-4 flex flex-wrap items-end gap-2 border-t border-slate-100 pt-4"
          action={async (fd) => {
            setError(null);
            const r = await assignClubTeamMemberAction(fd);
            if (r.ok) router.refresh();
            else setError(r.error);
          }}
        >
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="user_id" value={member.userId} />
          <label className="sr-only" htmlFor={`add-team-${member.userId}`}>
            Add to team
          </label>
          <select
            id={`add-team-${member.userId}`}
            name="team_id"
            className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
            defaultValue=""
            required
          >
            <option value="" disabled>
              Add to team…
            </option>
            {availableToAdd.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
          <button type="submit" className="btn-secondary text-xs">
            Add
          </button>
        </form>
      ) : null}
    </section>
  );
}

function MemberProfileSkillsInterestsBlock({
  clubId,
  member,
  canEdit,
}: {
  clubId: string;
  member: ClubMember;
  canEdit: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const entries = member.skillInterestEntries ?? [];
  const skills = entries.filter((e) => e.kind === "skill");
  const interests = entries.filter((e) => e.kind === "interest");

  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Skills & interests</h3>
      <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-slate-500">
        What they bring and what they want to help with — club-specific, separate from leadership tags.
      </p>

      <div className="mt-4 grid gap-6 sm:grid-cols-2 sm:gap-8">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-violet-700">Skills</p>
          {skills.length > 0 ? (
            <ul className="mt-1.5 flex flex-wrap gap-2">
              {skills.map((s) => (
                <li
                  key={s.id}
                  className="inline-flex items-center gap-0.5 rounded-full border border-violet-200 bg-violet-50 px-2.5 py-1 text-xs font-semibold text-violet-950"
                >
                  <span>{s.label}</span>
                  {canEdit ? (
                    <button
                      type="button"
                      className="ml-0.5 rounded px-1 text-violet-800 hover:bg-violet-100"
                      aria-label={`Remove ${s.label}`}
                      onClick={async () => {
                        const fd = new FormData();
                        fd.set("club_id", clubId);
                        fd.set("entry_id", s.id);
                        setError(null);
                        const r = await deleteClubMemberSkillInterestAction(fd);
                        if (r.ok) router.refresh();
                        else setError(r.error);
                      }}
                    >
                      ×
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1 text-sm text-slate-500">None listed yet.</p>
          )}
        </div>

        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-amber-800">Interests</p>
          {interests.length > 0 ? (
            <ul className="mt-1.5 flex flex-wrap gap-2">
              {interests.map((s) => (
                <li
                  key={s.id}
                  className="inline-flex items-center gap-0.5 rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-950"
                >
                  <span>{s.label}</span>
                  {canEdit ? (
                    <button
                      type="button"
                      className="ml-0.5 rounded px-1 text-amber-900 hover:bg-amber-100"
                      aria-label={`Remove ${s.label}`}
                      onClick={async () => {
                        const fd = new FormData();
                        fd.set("club_id", clubId);
                        fd.set("entry_id", s.id);
                        setError(null);
                        const r = await deleteClubMemberSkillInterestAction(fd);
                        if (r.ok) router.refresh();
                        else setError(r.error);
                      }}
                    >
                      ×
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1 text-sm text-slate-500">None listed yet.</p>
          )}
        </div>
      </div>

      {error ? <p className="mt-3 text-sm text-red-600">{error}</p> : null}

      {canEdit ? (
        <div className="mt-6 grid gap-4 border-t border-slate-100 pt-6 sm:grid-cols-2 sm:gap-6">
          <form
            className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-end"
            action={async (fd) => {
              setError(null);
              const r = await addClubMemberSkillInterestAction(fd);
              if (r.ok) router.refresh();
              else setError(r.error);
            }}
          >
            <input type="hidden" name="club_id" value={clubId} />
            <input type="hidden" name="user_id" value={member.userId} />
            <input type="hidden" name="kind" value="skill" />
            <label className="sr-only" htmlFor={`add-skill-${member.userId}`}>
              Add skill
            </label>
            <input
              id={`add-skill-${member.userId}`}
              name="label"
              placeholder="Add a skill"
              className="min-h-[42px] min-w-0 flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900"
              maxLength={80}
              autoComplete="off"
            />
            <button type="submit" className="btn-secondary shrink-0 px-4 py-2 text-sm">
              Add skill
            </button>
          </form>
          <form
            className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-end"
            action={async (fd) => {
              setError(null);
              const r = await addClubMemberSkillInterestAction(fd);
              if (r.ok) router.refresh();
              else setError(r.error);
            }}
          >
            <input type="hidden" name="club_id" value={clubId} />
            <input type="hidden" name="user_id" value={member.userId} />
            <input type="hidden" name="kind" value="interest" />
            <label className="sr-only" htmlFor={`add-interest-${member.userId}`}>
              Add interest
            </label>
            <input
              id={`add-interest-${member.userId}`}
              name="label"
              placeholder="Add an interest"
              className="min-h-[42px] min-w-0 flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900"
              maxLength={80}
              autoComplete="off"
            />
            <button type="submit" className="btn-secondary shrink-0 px-4 py-2 text-sm">
              Add interest
            </button>
          </form>
        </div>
      ) : null}
    </section>
  );
}

const AVAILABILITY_WEEKDAY_OPTIONS: { value: number; label: string }[] = [
  { value: 1, label: "Monday" },
  { value: 2, label: "Tuesday" },
  { value: 3, label: "Wednesday" },
  { value: 4, label: "Thursday" },
  { value: 5, label: "Friday" },
  { value: 6, label: "Saturday" },
  { value: 7, label: "Sunday" },
];

function MemberProfileAvailabilityBlock({
  clubId,
  member,
  canEdit,
}: {
  clubId: string;
  member: ClubMember;
  canEdit: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [windowMode, setWindowMode] = useState<"allday" | "range">("allday");
  const slots = member.availabilitySlots ?? [];

  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Weekly availability</h3>
      <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-slate-500">
        Typical times you can participate in club activities — recurring pattern only, not a calendar or RSVP
        substitute. Times are simple local “wall clock” hours.
      </p>

      {slots.length > 0 ? (
        <ul className="mt-3 space-y-2">
          {slots.map((s) => (
            <li
              key={s.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-slate-50/80 px-3 py-2.5 text-sm text-slate-800"
            >
              <span className="font-medium">{formatAvailabilitySlotLine(s)}</span>
              {canEdit ? (
                <button
                  type="button"
                  className="shrink-0 text-xs font-semibold text-red-600 underline-offset-2 hover:underline"
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("entry_id", s.id);
                    setError(null);
                    const r = await deleteClubMemberAvailabilitySlotAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  Remove
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-sm text-slate-500">No weekly availability shared yet.</p>
      )}

      {error ? <p className="mt-2 text-sm text-red-600">{error}</p> : null}

      {canEdit ? (
        <form
          className="mt-5 space-y-4 border-t border-slate-100 pt-5"
          action={async (fd) => {
            setError(null);
            const r = await addClubMemberAvailabilitySlotAction(fd);
            if (r.ok) {
              setWindowMode("allday");
              router.refresh();
            } else setError(r.error);
          }}
        >
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="user_id" value={member.userId} />
          <input type="hidden" name="window" value={windowMode} />

          <p className="text-xs font-semibold uppercase tracking-wide text-slate-600">Add a slot</p>

          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-xs font-semibold text-slate-600">
              Weekday
              <select
                name="day_of_week"
                className="mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900"
                required
                defaultValue={1}
              >
                {AVAILABILITY_WEEKDAY_OPTIONS.map((d) => (
                  <option key={d.value} value={d.value}>
                    {d.label}
                  </option>
                ))}
              </select>
            </label>

            <fieldset className="min-w-0 space-y-2">
              <legend className="text-xs font-semibold text-slate-600">Type</legend>
              <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-800">
                <input
                  type="radio"
                  className="h-4 w-4 border-slate-300 text-indigo-600 focus:ring-indigo-500"
                  checked={windowMode === "allday"}
                  onChange={() => setWindowMode("allday")}
                />
                All day / flexible
              </label>
              <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-800">
                <input
                  type="radio"
                  className="h-4 w-4 border-slate-300 text-indigo-600 focus:ring-indigo-500"
                  checked={windowMode === "range"}
                  onChange={() => setWindowMode("range")}
                />
                Specific hours
              </label>
            </fieldset>
          </div>

          {windowMode === "range" ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block text-xs font-semibold text-slate-600">
                From
                <input
                  name="time_start"
                  type="time"
                  required
                  className="mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900"
                />
              </label>
              <label className="block text-xs font-semibold text-slate-600">
                To
                <input
                  name="time_end"
                  type="time"
                  required
                  className="mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900"
                />
              </label>
            </div>
          ) : null}

          <button type="submit" className="btn-secondary px-4 py-2 text-sm">
            Add availability
          </button>
        </form>
      ) : null}
    </section>
  );
}

const DUES_STATUS_OPTIONS = [
  { value: "unset", label: "Not set" },
  { value: "unpaid", label: "Unpaid" },
  { value: "partial", label: "Partial" },
  { value: "paid", label: "Paid" },
  { value: "exempt", label: "Exempt" },
  { value: "waived", label: "Waived" },
] as const;

function formatDuesStatusLabel(status: ClubMemberDuesRecord["status"]): string {
  switch (status) {
    case "unpaid":
      return "Unpaid";
    case "paid":
      return "Paid";
    case "partial":
      return "Partial";
    case "exempt":
      return "Exempt";
    case "waived":
      return "Waived";
    default:
      return status;
  }
}

function MemberProfileDuesBlock({
  clubId,
  member,
  initialRecord,
  duesTerm,
  canEdit,
}: {
  clubId: string;
  member: ClubMember;
  initialRecord: ClubMemberDuesRecord | null;
  duesTerm: ClubDuesSettings | null;
  canEdit: boolean;
}) {
  const router = useRouter();
  const pastDueHintId = useId();
  const [error, setError] = useState<string | null>(null);
  const [statusDraft, setStatusDraft] = useState<string>(initialRecord ? initialRecord.status : "unset");
  const [notesDraft, setNotesDraft] = useState(initialRecord?.notes ?? "");

  useEffect(() => {
    setStatusDraft(initialRecord ? initialRecord.status : "unset");
    setNotesDraft(initialRecord?.notes ?? "");
  }, [member.userId, initialRecord]);

  async function submit(status: string, notes: string) {
    setError(null);
    const fd = new FormData();
    fd.set("club_id", clubId);
    fd.set("target_user_id", member.userId);
    fd.set("status", status);
    fd.set("notes", notes);
    const r = await setClubMemberDuesAction(fd);
    if (r.ok) {
      if (status === "unset") {
        setStatusDraft("unset");
        setNotesDraft("");
      }
      router.refresh();
    } else {
      setError(r.error);
    }
  }

  const hasRow = Boolean(initialRecord);
  const updatedLabel =
    initialRecord?.updatedAt && !Number.isNaN(new Date(initialRecord.updatedAt).getTime())
      ? new Date(initialRecord.updatedAt).toLocaleString()
      : null;

  const statusForPastDueHint = canEdit ? statusDraft : (initialRecord?.status ?? "unset");
  const showPastDueHint =
    Boolean(duesTerm?.dueDate)
    && statusForPastDueHint === "unpaid"
    && isUnpaidDuesPastDue("unpaid", duesTerm?.dueDate);

  const duesIntro = canEdit
    ? "Leadership-only. Roster chips match the statuses below (Unpaid shows as Past due after the term due date). Not shown to regular members or in roster CSV export."
    : "Leadership-only. Read-only while this club is archived. Not shown to regular members or in roster CSV export.";

  return (
    <section className="rounded-xl border border-teal-200 bg-teal-50/60 p-4 sm:p-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-teal-950">Dues</h3>
      <p className="mt-1 text-xs leading-relaxed text-teal-950/85">{duesIntro}</p>

      {duesTerm ? (
        <div className="mt-3 rounded-xl border border-teal-200/80 bg-white/90 px-3 py-3 sm:px-4">
          <p className="text-[10px] font-bold uppercase tracking-wider text-teal-900/75">Club dues term</p>
          <p className="mt-1.5 break-words text-sm font-semibold leading-snug text-slate-900" title={duesTerm.label}>
            {duesTerm.label}
          </p>
          <p className="mt-1.5 text-sm leading-relaxed text-slate-600">{formatDuesTermMoneyAndDue(duesTerm)}</p>
        </div>
      ) : (
        <p className="mt-3 rounded-lg border border-dashed border-teal-200/70 bg-white/50 px-3 py-2 text-xs leading-relaxed text-teal-950/90">
          No club-wide term on file — set it from the Members page (Club dues card) so amount and due date match the
          summary there and on profiles.
        </p>
      )}

      {error ? <p className="mt-2 text-sm text-red-700">{error}</p> : null}

      {!canEdit && showPastDueHint ? (
        <p
          className="mt-3 rounded-lg border border-amber-200/80 bg-amber-50/90 px-2.5 py-2 text-xs leading-relaxed text-amber-950"
          id={pastDueHintId}
        >
          <span className="font-semibold">Past due:</span> Unpaid after the term due date — same rule as the roster chip.
        </p>
      ) : null}

      {canEdit ? (
        <>
          <label htmlFor={`dues-status-${member.userId}`} className="mt-3 block text-xs font-semibold text-teal-950">
            Member status
          </label>
          <select
            id={`dues-status-${member.userId}`}
            value={statusDraft}
            onChange={(e) => setStatusDraft(e.target.value)}
            aria-describedby={showPastDueHint ? pastDueHintId : undefined}
            className="mt-1.5 w-full rounded-lg border border-teal-200/90 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-teal-400 focus:outline-none focus:ring-2 focus:ring-teal-200"
          >
            {DUES_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          {showPastDueHint ? (
            <p
              className="mt-2 rounded-lg border border-amber-200/80 bg-amber-50/90 px-2.5 py-2 text-xs leading-relaxed text-amber-950"
              id={pastDueHintId}
            >
              <span className="font-semibold">Past due:</span> still{" "}
              <span className="font-medium">Unpaid</span> after the term due date — update when payment is received.
            </p>
          ) : null}

          <label htmlFor={`dues-notes-${member.userId}`} className="mt-3 block text-xs font-semibold text-teal-950">
            Notes (optional)
          </label>
          <textarea
            id={`dues-notes-${member.userId}`}
            value={notesDraft}
            onChange={(e) => setNotesDraft(e.target.value)}
            rows={3}
            maxLength={500}
            placeholder="e.g. payment plan, semester, check #…"
            className="mt-1.5 w-full resize-y rounded-lg border border-teal-200/90 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-teal-400 focus:outline-none focus:ring-2 focus:ring-teal-200"
          />
          <p className="mt-1 text-[11px] text-teal-950/70">{notesDraft.length} / 500 characters</p>

          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              className="btn-secondary px-4 py-2 text-sm"
              onClick={() => submit(statusDraft, notesDraft)}
            >
              Save dues
            </button>
            <button
              type="button"
              className="btn-secondary border-slate-200 px-4 py-2 text-sm text-slate-700"
              onClick={() => submit("unset", "")}
              disabled={!hasRow && statusDraft === "unset" && notesDraft.trim() === ""}
            >
              Clear dues
            </button>
          </div>
        </>
      ) : (
        <>
          {initialRecord ? (
            <div className="mt-3 space-y-2 rounded-lg border border-teal-200/80 bg-white/90 px-3 py-2.5 text-sm text-slate-800">
              <p>
                <span className="font-semibold text-teal-950">Status:</span>{" "}
                {formatDuesStatusLabel(initialRecord.status)}
              </p>
              {initialRecord.notes.trim() ? (
                <p className="whitespace-pre-wrap">
                  <span className="font-semibold text-teal-950">Notes:</span> {initialRecord.notes}
                </p>
              ) : null}
              {updatedLabel ? (
                <p className="text-xs text-slate-500">Last updated {updatedLabel}</p>
              ) : null}
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-600">No dues status on file.</p>
          )}
          <p className="mt-2 text-xs font-medium text-teal-950/80">
            This club is archived — dues cannot be edited.
          </p>
        </>
      )}
    </section>
  );
}

function MemberProfileParticipationScoreSection({ member }: { member: ClubMember }) {
  const participation = computeParticipationScore({
    attendanceRate: member.attendanceRate,
    totalTrackedEvents: member.totalTrackedEvents,
    volunteerHoursTotal: member.volunteerHoursTotal,
  });
  const band = participationScoreBand(participation.score);
  const bandRing =
    band === "high"
      ? "from-emerald-500 to-teal-600"
      : band === "mid"
        ? "from-amber-500 to-orange-500"
        : "from-slate-400 to-slate-600";
  const volHours = Number.isFinite(member.volunteerHoursTotal) ? member.volunteerHoursTotal : 0;
  const hoursLabel = Number.isInteger(volHours) ? String(volHours) : volHours.toFixed(1);

  return (
    <section className="rounded-xl border border-slate-200 bg-gradient-to-br from-white to-slate-50/80 p-4 sm:p-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Participation score</h3>
      <p className="mt-1 text-xs leading-relaxed text-slate-600">{PARTICIPATION_SCORE_SUBTITLE}</p>
      <div className="mt-4 flex flex-wrap items-center gap-4">
        <div
          className={`flex h-[4.5rem] w-[4.5rem] shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br text-xl font-bold text-white shadow-sm ${bandRing}`}
          aria-label={`Participation score ${participation.score} out of 100`}
        >
          {participation.score}
        </div>
        <div className="min-w-0 flex-1 text-sm text-slate-700">
          <p className="font-medium text-slate-900">Out of 100</p>
          {participation.attendanceSignalLimited ? (
            <p className="mt-1 text-xs text-amber-800">
              No tracked past events yet — the attendance portion of the score uses a neutral placeholder until the club
              records attendance.
            </p>
          ) : (
            <p className="mt-1 text-xs text-slate-600">
              Higher when marked present at more tracked events and when volunteer hours are logged (see breakdown).
            </p>
          )}
        </div>
      </div>
      <details className="mt-4 rounded-lg border border-slate-100 bg-slate-50/80 px-3 py-2 text-xs text-slate-600">
        <summary className="cursor-pointer font-semibold text-slate-700">How this is calculated</summary>
        <ul className="mt-2 list-disc space-y-1.5 pl-4 leading-relaxed">
          <li>
            About <span className="font-medium text-slate-800">75%</span> of the score comes from the same{" "}
            <span className="font-medium text-slate-800">tracked attendance rate</span> as in the Attendance section
            {participation.attendanceSignalLimited
              ? " (when no tracked events exist yet, a neutral midpoint fills this slice)."
              : ` — currently ${member.attendanceRate}% (${member.attendanceCount} of ${member.totalTrackedEvents} events).`}
          </li>
          <li>
            About <span className="font-medium text-slate-800">25%</span> comes from volunteer hours logged in this club,
            up to {PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE} h for the full slice ({hoursLabel} h on file).
          </li>
        </ul>
      </details>
    </section>
  );
}

function MemberProfileOfficerNotesBlock({
  clubId,
  member,
  initialBody,
  canEdit,
}: {
  clubId: string;
  member: ClubMember;
  initialBody: string;
  canEdit: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState(initialBody);

  useEffect(() => {
    setDraft(initialBody);
  }, [member.userId, initialBody]);

  async function submitBody(body: string) {
    setError(null);
    const fd = new FormData();
    fd.set("club_id", clubId);
    fd.set("target_user_id", member.userId);
    fd.set("body", body);
    const r = await setClubMemberOfficerNoteAction(fd);
    if (r.ok) {
      if (body.trim() === "") setDraft("");
      router.refresh();
    } else {
      setError(r.error);
    }
  }

  return (
    <section className="rounded-xl border border-amber-200 bg-amber-50/70 p-4 sm:p-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-amber-950">Internal officer note</h3>
      <p className="mt-1 text-xs leading-relaxed text-amber-950/85">
        Leadership-only — not visible to members on the roster or in their own profile.
      </p>

      {error ? <p className="mt-2 text-sm text-red-700">{error}</p> : null}

      {canEdit ? (
        <>
          <label htmlFor={`officer-note-${member.userId}`} className="sr-only">
            Internal officer note
          </label>
          <textarea
            id={`officer-note-${member.userId}`}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={5}
            maxLength={4000}
            placeholder="Operational context for leadership only…"
            className="mt-3 w-full resize-y rounded-lg border border-amber-200/90 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-amber-400 focus:outline-none focus:ring-2 focus:ring-amber-200"
          />
          <p className="mt-1 text-[11px] text-amber-950/70">{draft.length} / 4000 characters</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              className="btn-secondary px-4 py-2 text-sm"
              onClick={() => submitBody(draft)}
            >
              Save note
            </button>
            <button
              type="button"
              className="btn-secondary border-slate-200 px-4 py-2 text-sm text-slate-700"
              onClick={() => submitBody("")}
              disabled={initialBody.trim() === "" && draft.trim() === ""}
            >
              Clear note
            </button>
          </div>
        </>
      ) : (
        <>
          {initialBody.trim() ? (
            <p className="mt-3 whitespace-pre-wrap rounded-lg border border-amber-200/80 bg-white/90 px-3 py-2.5 text-sm leading-relaxed text-slate-800">
              {initialBody}
            </p>
          ) : (
            <p className="mt-3 text-sm text-slate-600">No internal note on file.</p>
          )}
          <p className="mt-2 text-xs font-medium text-amber-950/80">
            This club is archived — notes cannot be edited.
          </p>
        </>
      )}
    </section>
  );
}

/**
 * Lightweight member profile: modal overlay (portal) for roster.
 * Auth email is shown only on the signed-in member’s own profile; optional club phone is never on the roster list.
 */
export function MemberProfileDialog({
  open,
  onClose,
  member,
  clubId,
  currentUserId,
  rbacRoles,
  isPresident,
  isArchived,
  canAssignRoles,
  canRemoveMembers,
  memberTagDefinitions,
  canManageMemberTags,
  clubCommittees,
  canManageCommittees,
  clubTeams,
  canManageTeams,
  canManageVolunteerHours,
  canManageMemberSkillsForOthers,
  canManageMemberAvailabilityForOthers,
  canManageOfficerNotes,
  officerNotesByUserId,
  canManageMemberDues,
  duesByUserId,
  duesSettings = null,
  attendanceHistoryByUserId,
  canViewMemberContact,
  canSeeInactiveEngagement = false,
  canViewOthersMemberAttendanceHistory = false,
}: MemberProfileDialogProps) {
  const [mounted, setMounted] = useState(false);
  const titleId = useId();

  useEffect(() => setMounted(true), []);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!mounted || !open || !member) {
    return null;
  }

  const isCurrentUser = member.userId === currentUserId;
  const isAlumni = member.membershipStatus === "alumni";
  const isOfficer = member.role === "officer" && !isAlumni;
  const significantRbacRoles = rbacRoles.filter(
    (r) => !(r.isSystem && (r.roleName === "Officer" || r.roleName === "Member")),
  );
  const showManagement = !isArchived && !isCurrentUser && (canAssignRoles || canRemoveMembers);
  const showTagManagement = canManageMemberTags && !isArchived;
  const showCommitteeManagement = canManageCommittees && !isArchived;
  const showTeamManagement = canManageTeams && !isArchived;
  const canEditSkillsInterests =
    !isArchived && ((!isAlumni && isCurrentUser) || canManageMemberSkillsForOthers);
  const canEditAvailability =
    !isArchived && ((!isAlumni && isCurrentUser) || canManageMemberAvailabilityForOthers);
  const joinedLabel = formatJoinedAt(member.joinedAt);
  const shouldLoadClubContact = isCurrentUser || canViewMemberContact;
  const canEditClubContact = isCurrentUser && !isAlumni && !isArchived;
  const attendanceEntries = attendanceHistoryByUserId?.[member.userId] ?? [];
  const showOthersAttendanceEventHistory = isCurrentUser || canViewOthersMemberAttendanceHistory;

  const panel = (
    <div
      className="fixed inset-0 z-[100] flex items-end justify-center p-0 sm:items-center sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      <button
        type="button"
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-[2px]"
        aria-label="Close profile"
        onClick={onClose}
      />

      <div className="relative z-10 flex max-h-[min(92vh,880px)] w-full max-w-2xl flex-col overflow-hidden rounded-t-2xl border border-slate-200 bg-white shadow-2xl sm:max-w-3xl sm:rounded-2xl lg:max-w-4xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 bg-gradient-to-br from-slate-50 to-indigo-50/40 px-6 py-5 sm:px-8">
          <div className="flex min-w-0 items-start gap-3">
            <div
              className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl text-lg font-bold text-white shadow-sm ${
                isOfficer ? "bg-gradient-to-br from-indigo-600 to-violet-600" : "bg-gradient-to-br from-slate-600 to-slate-700"
              } ${isCurrentUser ? "ring-2 ring-indigo-300 ring-offset-2" : ""}`}
            >
              {getMemberRosterInitials(member)}
            </div>
            <div className="min-w-0 pt-0.5">
              <p className="section-kicker text-slate-600">Member</p>
              <h2
                id={titleId}
                className="text-lg font-bold tracking-tight text-slate-900 sm:text-xl lg:text-2xl"
              >
                {getMemberRosterDisplayName(member)}
              </h2>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>{member.role}</span>
                {isAlumni ? (
                  <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-900">
                    Alumni
                  </span>
                ) : (
                  <span className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-800">
                    Active
                  </span>
                )}
                {isCurrentUser ? <span className="member-you-pill">You</span> : null}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-10 min-w-10 shrink-0 items-center justify-center rounded-xl text-slate-500 transition hover:bg-slate-200/80 hover:text-slate-800"
            aria-label="Close"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5 sm:px-8 sm:py-6">
          <div className="flex flex-col gap-8">
          {isCurrentUser && member.email ? (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Your account</h3>
              <p className="mt-1.5 break-all text-sm leading-relaxed text-slate-800">{member.email}</p>
              <p className="mt-2 text-xs text-slate-600">
                This is your school sign-in email. Optional phone for this club is saved separately below.
              </p>
            </section>
          ) : !isCurrentUser && !canViewMemberContact ? (
            <p className="text-sm leading-relaxed text-slate-500">
              Other members’ school emails and phone numbers are not shown here. Leadership can open optional club contact
              when their role allows it.
            </p>
          ) : null}

          <MemberProfileContactBlock
            clubId={clubId}
            memberUserId={member.userId}
            dialogOpen={open}
            shouldFetch={shouldLoadClubContact}
            canEdit={canEditClubContact}
            isAlumniSelf={isCurrentUser && isAlumni}
          />

          {joinedLabel ? (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">In this club since</h3>
              <p className="mt-1.5 text-sm font-medium text-slate-800">{joinedLabel}</p>
            </section>
          ) : null}

          <section
            className="space-y-5 rounded-2xl border border-slate-200/90 bg-slate-50/50 p-4 sm:p-5"
            aria-labelledby="member-engagement-heading"
          >
            <div>
              <h2
                id="member-engagement-heading"
                className="text-xs font-semibold uppercase tracking-wide text-slate-500"
              >
                Engagement &amp; participation
              </h2>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{MEMBER_ENGAGEMENT_SECTION_INTRO}</p>
            </div>

            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Attendance</h3>
              <p className="mt-1 text-xs leading-relaxed text-slate-500">{TRACKED_ATTENDANCE_SUBTITLE}</p>
              {member.totalTrackedEvents > 0 ? (
                <div className="mt-2">
                  <p className="text-sm font-medium text-slate-800">
                    {formatTrackedAttendanceSummary({
                      attendanceCount: member.attendanceCount,
                      totalTrackedEvents: member.totalTrackedEvents,
                      attendanceRate: member.attendanceRate,
                    })}
                  </p>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-emerald-500"
                      style={{ width: `${member.attendanceRate}%` }}
                    />
                  </div>
                </div>
              ) : (
                <p className="mt-2 text-sm text-slate-500">{trackedAttendanceEmptyCopy()}</p>
              )}

              <h4 className="mt-4 text-[11px] font-semibold uppercase tracking-wide text-slate-500">Event history</h4>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
                Listed events are ones where this member was marked present.
              </p>
              {!showOthersAttendanceEventHistory ? (
                <p className="mt-2 text-sm text-slate-500">
                  Per-event history for other members is limited to people with attendance or insights access. Open your
                  own profile to see yours.
                </p>
              ) : attendanceEntries.length > 0 ? (
                <ul className="mt-2 max-h-64 divide-y divide-slate-100 overflow-y-auto rounded-xl border border-slate-200 bg-white/80">
                  {attendanceEntries.map((row) => {
                    const when = parseEventInstant(row.eventDateIso);
                    const marked = row.markedAtIso ? parseEventInstant(row.markedAtIso) : null;
                    const showMarked =
                      marked !== null && !Number.isNaN(marked.getTime());
                    return (
                      <li key={row.eventId} className="flex flex-wrap items-start justify-between gap-2 px-3 py-2.5 sm:px-4">
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-slate-900">{row.title}</p>
                          <p className="mt-0.5 text-xs text-slate-600">
                            {formatEventDateMedium(when)} · {formatEventTimeShort(when)}
                          </p>
                          {showMarked && marked ? (
                            <p className="mt-1 text-[11px] text-slate-400">
                              Marked present {formatEventDateMedium(marked)} · {formatEventTimeShort(marked)}
                            </p>
                          ) : null}
                        </div>
                        <span className="shrink-0 self-start rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-800">
                          Present
                        </span>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <p className="mt-2 text-sm text-slate-500">
                  {member.totalTrackedEvents > 0
                    ? "No presence marks yet — this member wasn’t marked present at any tracked past events."
                    : "When the club tracks attendance on past events, events where this member was marked present appear here."}
                </p>
              )}
            </section>

            <MemberProfileParticipationScoreSection member={member} />

            <VolunteerHoursPanel clubId={clubId} member={member} canManage={canManageVolunteerHours} variant="default" />
          </section>

          {canSeeInactiveEngagement
            ? (() => {
                const engagementBlock = buildLeadershipEngagementProfileBlock({
                  membershipStatus: member.membershipStatus,
                  likelyInactive: member.likelyInactive,
                  lastEngagementAt: member.lastEngagementAt,
                  engagementSignalWeak: member.engagementSignalWeak,
                });
                if (!engagementBlock) return null;
                if (engagementBlock.level === "flagged") {
                  return (
                    <section
                      className="rounded-xl border border-amber-200 bg-amber-50/85 p-4 sm:p-5"
                      aria-label="Likely inactive member hint"
                    >
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-amber-950">
                        {engagementBlock.title}
                      </h3>
                      <p className="mt-1 text-[11px] font-medium uppercase tracking-wide text-amber-900/90">
                        Leadership · RSVP &amp; event recency
                      </p>
                      <p className="mt-2 text-sm leading-relaxed text-amber-950/90">{engagementBlock.body}</p>
                      <p className="mt-2 text-xs font-medium text-amber-900/80">
                        Nothing here removes members or changes roles — use outreach or roster actions when appropriate.
                      </p>
                    </section>
                  );
                }
                return (
                  <section className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 sm:p-5">
                    <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Leadership · RSVP &amp; event recency
                    </h3>
                    <p className="mt-2 text-sm leading-relaxed text-slate-700">{engagementBlock.body}</p>
                  </section>
                );
              })()
            : null}

          {significantRbacRoles.length > 0 ? (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Roles</h3>
              <ul className="mt-2 flex flex-wrap gap-2">
                {significantRbacRoles.map((r) => (
                  <li
                    key={r.roleId}
                    className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold ${
                      r.roleName === "President"
                        ? "border-violet-200 bg-violet-50 text-violet-700"
                        : "border-emerald-200 bg-emerald-50 text-emerald-700"
                    }`}
                  >
                    {r.roleName}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          <MemberProfileTagsBlock
            clubId={clubId}
            member={member}
            memberTagDefinitions={memberTagDefinitions}
            canManage={showTagManagement}
          />

          <MemberProfileCommitteesBlock
            clubId={clubId}
            member={member}
            clubCommittees={clubCommittees}
            canManage={showCommitteeManagement}
          />

          <MemberProfileTeamsBlock
            clubId={clubId}
            member={member}
            clubTeams={clubTeams}
            canManage={showTeamManagement}
          />

          <MemberProfileSkillsInterestsBlock clubId={clubId} member={member} canEdit={canEditSkillsInterests} />

          <MemberProfileAvailabilityBlock clubId={clubId} member={member} canEdit={canEditAvailability} />

          {canManageMemberDues ? (
            <MemberProfileDuesBlock
              clubId={clubId}
              member={member}
              initialRecord={duesByUserId?.[member.userId] ?? null}
              duesTerm={duesSettings ?? null}
              canEdit={!isArchived}
            />
          ) : null}

          {canManageOfficerNotes ? (
            <MemberProfileOfficerNotesBlock
              clubId={clubId}
              member={member}
              initialBody={officerNotesByUserId?.[member.userId] ?? ""}
              canEdit={!isArchived}
            />
          ) : null}

          {isPresident && !isAlumni ? (
            <p className="text-sm text-slate-500">
              <Link href={`/clubs/${clubId}/settings`} className="font-semibold text-indigo-700 underline-offset-2 hover:underline">
                Manage roles in Settings
              </Link>
            </p>
          ) : null}
          </div>
        </div>

        {showManagement ? (
          <div className="border-t border-slate-100 bg-slate-50/80 px-6 py-5 sm:px-8">
            <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Actions</p>
            <div className="flex flex-wrap gap-2">
              {canAssignRoles && member.membershipStatus === "active" &&
                (member.role === "member" ? (
                  <form action={updateMemberRoleAction}>
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="user_id" value={member.userId} />
                    <input type="hidden" name="role" value="officer" />
                    <button type="submit" className="btn-secondary text-xs">
                      Promote to Officer
                    </button>
                  </form>
                ) : (
                  <form action={updateMemberRoleAction}>
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="user_id" value={member.userId} />
                    <input type="hidden" name="role" value="member" />
                    <button type="submit" className="btn-secondary text-xs">
                      Demote to Member
                    </button>
                  </form>
                ))}
              {canRemoveMembers && member.membershipStatus === "active" && (
                <form action={markMemberAlumniAction}>
                  <input type="hidden" name="club_id" value={clubId} />
                  <input type="hidden" name="user_id" value={member.userId} />
                  <button type="submit" className="btn-secondary text-xs">
                    Mark as alumni
                  </button>
                </form>
              )}
              {canRemoveMembers && (
                <form action={removeMemberAction}>
                  <input type="hidden" name="club_id" value={clubId} />
                  <input type="hidden" name="user_id" value={member.userId} />
                  <button type="submit" className="btn-danger text-xs">
                    {isAlumni ? "Remove from roster" : "Remove from club"}
                  </button>
                </form>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );

  return createPortal(panel, document.body);
}
