import Link from "next/link";
import { EventSummaryListLink } from "@/components/ui/event-summary";
import { PageIntro } from "@/components/ui/page-intro";
import { PageEmptyState } from "@/components/ui/page-patterns";
import { getDashboardData } from "@/lib/clubs/queries";

export default async function EventsPage() {
  const { upcomingEvents } = await getDashboardData();

  return (
    <section className="space-y-4 lg:space-y-6">
      <PageIntro
        kicker="Global"
        title="Events"
        description="Upcoming events across your clubs, with direct links into each club workspace."
        actions={
          <Link href="/dashboard" className="btn-secondary">
            Back to Dashboard
          </Link>
        }
      />

      {upcomingEvents.length === 0 ? (
        <PageEmptyState
          title="No upcoming events yet"
          copy="Upcoming events across your clubs appear here. Create your first event so members can RSVP and stay in sync."
          action={
            <Link href="/my-clubs" className="btn-primary">
              Create your first event
            </Link>
          }
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)]">
          {upcomingEvents.map((event) => (
            <div key={event.id} className="border-b border-slate-100 last:border-b-0">
              <EventSummaryListLink
                href={`/clubs/${event.clubId}/events`}
                title={event.title}
                clubName={event.clubName}
                eventType={event.eventType}
                at={event.eventDateRaw}
                location={event.location}
              />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
