import type { ClubDetail } from "@/lib/clubs/queries";
import { DisclosurePanel } from "@/components/ui/disclosure-panel";
import { getMemberDisplayName, getMemberInitials } from "@/lib/member-display";
import { computeClubInsights } from "@/lib/clubs/insights";
import type { TrendDirection, EngagementTier } from "@/lib/clubs/insights";

type ClubInsightsSectionProps = {
  club: ClubDetail;
};

// ─── Small helpers ────────────────────────────────────────────────────────────

function trendBadgeClass(dir: TrendDirection): string {
  if (dir === "improving") return "feedback-pill feedback-pill-success";
  if (dir === "declining") return "feedback-pill feedback-pill-urgent";
  return "badge-soft";
}

function trendLabel(dir: TrendDirection, delta: number): string {
  if (dir === "improving") return `↑ Improving (+${delta}pp)`;
  if (dir === "declining") return `↓ Declining (${delta}pp)`;
  if (dir === "stable") return "→ Stable";
  return "Need more data";
}

function rateBarColor(rate: number): string {
  if (rate >= 70) return "bg-emerald-500";
  if (rate >= 40) return "bg-amber-400";
  return "bg-rose-400";
}

function tierBarColor(tier: EngagementTier): string {
  if (tier === "high") return "bg-emerald-500";
  if (tier === "moderate") return "bg-amber-400";
  return "bg-rose-400";
}

function tierBgClass(tier: EngagementTier): string {
  if (tier === "high") return "bg-emerald-50 border-emerald-100";
  if (tier === "moderate") return "bg-amber-50 border-amber-100";
  return "bg-rose-50 border-rose-100";
}

function tierTextClass(tier: EngagementTier): string {
  if (tier === "high") return "text-emerald-800";
  if (tier === "moderate") return "text-amber-800";
  return "text-rose-800";
}

function tierCountClass(tier: EngagementTier): string {
  if (tier === "high") return "text-emerald-700";
  if (tier === "moderate") return "text-amber-700";
  return "text-rose-700";
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ClubInsightsSection({ club }: ClubInsightsSectionProps) {
  const insights = computeClubInsights(club);
  const hasData = club.totalTrackedEvents > 0;
  const highlyEngaged = club.members.filter((m) => m.attendanceRate >= 70).length;

  return (
    <section className="space-y-6">

      {/* Page header */}
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-emerald-50 p-5 sm:p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Analysis</p>
          <h1 className="section-title mt-2 text-2xl sm:mt-3 sm:text-3xl md:text-4xl">Insights</h1>
          <p className="section-subtitle mt-3 max-w-2xl text-base sm:mt-4 sm:text-lg text-slate-700">
            Understand attendance patterns, member engagement, and which events work best for your club.
          </p>

          <div className="mt-6 grid grid-cols-2 gap-4 sm:mt-8 sm:flex sm:flex-wrap sm:items-center sm:gap-8">
            <div>
              <p className="text-2xl font-bold text-slate-900">{club.totalTrackedEvents}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {club.totalTrackedEvents === 1 ? "Event tracked" : "Events tracked"}
              </p>
            </div>

            {hasData && (
              <>
                <div className="hidden h-8 w-px bg-slate-200 sm:block" aria-hidden />
                <div>
                  <p className="text-2xl font-bold text-slate-900">{club.clubAverageAttendance}%</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Avg. attendance</p>
                </div>

                <div className="hidden h-8 w-px bg-slate-200 sm:block" aria-hidden />
                <div className="col-span-2 sm:col-span-1">
                  <p className="text-2xl font-bold text-slate-900">{highlyEngaged}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                    {highlyEngaged === 1 ? "High-engagement member" : "High-engagement members"}
                  </p>
                </div>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Empty state */}
      {!hasData ? (
        <div className="card-surface p-10 text-center">
          <div className="mx-auto max-w-xs">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100">
              <svg className="h-6 w-6 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <h3 className="mt-4 text-base font-semibold text-slate-900">No insights yet</h3>
            <p className="mt-2 text-sm text-slate-500">
              Mark attendance at past events to start building trends and engagement data for your club.
            </p>
          </div>
        </div>
      ) : (
        <>

          {/* Key highlights */}
          {insights.highlights.length > 0 && (
            <div className="card-surface p-6">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Takeaways</p>
                  <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">What stands out</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    A short summary of what the data is telling you right now.
                  </p>
                </div>
              </div>
              <ul className="mt-5 space-y-2.5">
                {insights.highlights.map((text, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-3 rounded-xl border border-emerald-100 bg-emerald-50/70 px-4 py-3"
                  >
                    <svg className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                    <p className="text-sm text-slate-700">{text}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="card-surface p-6">
            <DisclosurePanel
              title="Detailed charts & breakdowns"
              subtitle="Per-event attendance bars, effectiveness by event type, engagement tiers, and most active members."
              badge={
                <span className={trendBadgeClass(insights.trendDirection)}>
                  {trendLabel(insights.trendDirection, insights.trendDelta)}
                </span>
              }
            >
              {/* Attendance trend */}
              <div>
                <div className="mb-4 flex flex-wrap items-end justify-between gap-2 border-b border-slate-100 pb-3">
                  <div>
                    <p className="section-kicker">Trend</p>
                    <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Attendance over time</h2>
                    <p className="mt-1 text-sm text-slate-600">
                      Each bar is one tracked event (vs current membership).
                    </p>
                  </div>
                </div>

                {insights.trendPoints.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-6 text-center">
                    <p className="text-sm text-slate-500">No tracked past events yet.</p>
                  </div>
                ) : insights.trendPoints.length < 3 ? (
                  <>
                    <div className="space-y-3">
                      {insights.trendPoints.map((point) => (
                        <TrendBar key={point.eventId} point={point} />
                      ))}
                    </div>
                    <p className="mt-4 text-xs text-slate-400">
                      Track at least 3 events to see a trend direction.
                    </p>
                  </>
                ) : (
                  <div className="space-y-3">
                    {insights.trendPoints.map((point) => (
                      <TrendBar key={point.eventId} point={point} />
                    ))}
                  </div>
                )}
              </div>

              {/* Event type + Engagement — side by side on large screens */}
              <div className="mt-8 grid gap-6 lg:grid-cols-2">

            {/* Event type effectiveness */}
            <div className="rounded-xl border border-slate-100 bg-slate-50/40 p-5">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">By Type</p>
                  <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Event Effectiveness</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    Average attendance rate by event type.
                  </p>
                </div>
                <span className="badge-soft">{insights.eventTypeRows.length} {insights.eventTypeRows.length === 1 ? "type" : "types"}</span>
              </div>

              {insights.eventTypeRows.length === 0 ? (
                <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-5 text-center">
                  <p className="text-sm text-slate-500">No event type data yet.</p>
                </div>
              ) : (
                <div className="mt-5 space-y-4">
                  {insights.eventTypeRows.map((row, index) => (
                    <div key={row.type}>
                      <div className="mb-1.5 flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2">
                          {index === 0 && insights.eventTypeRows.length > 1 && (
                            <span className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800">
                              Best
                            </span>
                          )}
                          <span className="text-sm font-semibold text-slate-800">{row.type}</span>
                          <span className="text-xs text-slate-400">
                            {row.eventCount} {row.eventCount === 1 ? "event" : "events"}
                          </span>
                        </div>
                        <span className="text-sm font-bold text-slate-900">{row.avgRate}%</span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                        <div
                          className={`h-full rounded-full transition-[width] duration-500 ${rateBarColor(row.avgRate)}`}
                          style={{ width: `${row.avgRate}%` }}
                        />
                      </div>
                    </div>
                  ))}
                  {insights.eventTypeRows.length === 1 && (
                    <p className="text-xs text-slate-400">
                      Run multiple event types to compare effectiveness.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Engagement segmentation */}
            <div className="rounded-xl border border-slate-100 bg-slate-50/40 p-5">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Engagement</p>
                  <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Member Breakdown</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    How members are grouped by attendance rate.
                  </p>
                </div>
                <span className="badge-soft">{club.memberCount} total</span>
              </div>

              {insights.segments.length === 0 ? (
                <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-5 text-center">
                  <p className="text-sm text-slate-500">Track attendance to see engagement data.</p>
                </div>
              ) : (
                <div className="mt-5 space-y-3">
                  {insights.segments.map((seg) => (
                    <div
                      key={seg.tier}
                      className={`rounded-xl border p-4 ${tierBgClass(seg.tier)}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <p className={`text-sm font-semibold ${tierTextClass(seg.tier)}`}>{seg.label}</p>
                          <p className="mt-0.5 text-xs text-slate-500">{seg.description}</p>
                        </div>
                        <div className="text-right">
                          <p className={`text-xl font-bold ${tierCountClass(seg.tier)}`}>{seg.count}</p>
                          <p className="text-xs text-slate-400">{seg.percent}%</p>
                        </div>
                      </div>
                      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/60">
                        <div
                          className={`h-full rounded-full transition-[width] duration-500 ${tierBarColor(seg.tier)}`}
                          style={{ width: `${seg.percent}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

          </div>

              {/* Top members */}
              <div className="mt-8 border-t border-slate-100 pt-6">
                <div className="section-card-header">
                  <div>
                    <p className="section-kicker">People</p>
                    <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Most active members</h2>
                    <p className="mt-1 text-sm text-slate-600">Top 3 members by attendance rate.</p>
                  </div>
                  <span className="badge-soft">{club.topMembers.length} shown</span>
                </div>

                {club.topMembers.length === 0 ? (
                  <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-5 text-center">
                    <p className="text-sm text-slate-500">No attendance data to rank members yet.</p>
                  </div>
                ) : (
                  <ul className="mt-5 space-y-3">
                    {club.topMembers.map((member, index) => {
                      const isCurrentUser = member.userId === club.currentUserId;
                      const isOfficer = member.role === "officer";
                      return (
                        <li key={member.userId} className="surface-subcard p-4">
                          <div className="flex items-center gap-3">
                            <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-600">
                              {index + 1}
                            </span>
                            <div className={`member-avatar ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}>
                              {getMemberInitials(member)}
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <p className="truncate text-sm font-semibold text-slate-900">
                                  {getMemberDisplayName(member)}
                                </p>
                                <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>
                                  {member.role}
                                </span>
                                {isCurrentUser ? <span className="member-you-pill">You</span> : null}
                              </div>
                              <div className="mt-2">
                                <div className="mb-1 flex items-center justify-between gap-2">
                                  <span className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">Attendance</span>
                                  <span className="text-xs font-semibold text-slate-600">
                                    {member.attendanceCount}/{member.totalTrackedEvents} · {member.attendanceRate}%
                                  </span>
                                </div>
                                <div className="h-1.5 overflow-hidden rounded-full bg-slate-100">
                                  <div
                                    className={`h-full rounded-full transition-[width] duration-500 ${rateBarColor(member.attendanceRate)}`}
                                    style={{ width: `${member.attendanceRate}%` }}
                                  />
                                </div>
                              </div>
                            </div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </DisclosurePanel>
          </div>

        </>
      )}

    </section>
  );
}

// ─── Trend bar sub-component ──────────────────────────────────────────────────

type TrendBarProps = {
  point: {
    eventId: string;
    title: string;
    eventType: string;
    date: string;
    presentCount: number;
    memberCount: number;
    rate: number;
  };
};

function TrendBar({ point }: TrendBarProps) {
  return (
    <div className="grid items-center gap-3 sm:grid-cols-[minmax(0,1fr)_8rem_2.5rem]">
      <div className="min-w-0">
        <p className="truncate text-sm font-semibold text-slate-800">{point.title}</p>
        <p className="text-xs text-slate-400">{point.eventType} · {point.date}</p>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-100">
        <div
          className={`h-full rounded-full transition-[width] duration-500 ${rateBarColor(point.rate)}`}
          style={{ width: `${point.rate}%` }}
        />
      </div>
      <p className="text-right text-sm font-bold text-slate-900">{point.rate}%</p>
    </div>
  );
}
