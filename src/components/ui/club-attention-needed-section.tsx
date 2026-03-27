import Link from "next/link";
import type { ClubAttentionAlert } from "@/lib/clubs/queries";

type ClubAttentionNeededSectionProps = {
  clubId: string;
  alerts: ClubAttentionAlert[];
};

function getAttentionAlertLabel(type: ClubAttentionAlert["type"]) {
  switch (type) {
    case "upcoming_event_low_rsvp":
      return "RSVP";
    case "no_upcoming_events":
      return "Schedule";
    case "no_recent_announcement":
      return "Updates";
    case "attendance_not_marked":
      return "Attendance";
    default:
      return "Alert";
  }
}

export function ClubAttentionNeededSection({ clubId, alerts }: ClubAttentionNeededSectionProps) {
  return (
    <section className="card-surface p-6" id="attention-needed">
      <div className="section-card-header">
        <div>
          <p className="section-kicker">Attention Needed</p>
          <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Next actions for officers</h2>
          <p className="mt-1 text-sm text-slate-600">A short list of the most relevant follow-ups for this club right now.</p>
        </div>
        <span className="badge-soft">{alerts.length} alerts</span>
      </div>

      {alerts.length === 0 ? (
        <div className="mt-4 rounded-xl border border-emerald-200 bg-gradient-to-br from-emerald-50 to-white p-6">
          <p className="font-semibold text-slate-900">Everything looks on track.</p>
          <p className="mt-1 text-sm text-slate-600">Your club has the main planning, update, and attendance follow-up covered right now.</p>
        </div>
      ) : (
        <div className="list-stack mt-4">
          {alerts.map((alert) => (
            <article key={alert.id} className="surface-subcard p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="max-w-2xl">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="badge-soft">{getAttentionAlertLabel(alert.type)}</span>
                    <h3 className="text-sm font-semibold text-slate-900">{alert.title}</h3>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-600">{alert.description}</p>
                </div>
                <Link href={`/clubs/${clubId}${alert.ctaTarget}`} className="btn-secondary whitespace-nowrap">
                  {alert.ctaLabel}
                </Link>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
