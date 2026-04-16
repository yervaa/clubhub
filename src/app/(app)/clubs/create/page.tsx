import Link from "next/link";
import { createClubAction } from "@/app/(app)/clubs/actions";
import { ActionFeedbackBanner } from "@/components/ui/action-feedback-banner";
import { FormDraftPersistence } from "@/components/ui/form-draft-persistence";

type CreateClubPageProps = {
  searchParams: Promise<{ error?: string }>;
};

export default async function CreateClubPage({ searchParams }: CreateClubPageProps) {
  const params = await searchParams;

  return (
    <section className="card-surface max-w-2xl p-8">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Club Setup</p>
      <h1 className="section-title mt-2">Start your club</h1>
      <p className="section-subtitle">Just add a name to get started. Add a short purpose now if you have one.</p>

      {params.error ? (
        <ActionFeedbackBanner
          variant="error"
          title="Could not create club yet"
          message={params.error}
          className="mt-6"
        />
      ) : null}

      <form id="create-club-form" action={createClubAction} className="mt-7 space-y-4">
        <div>
          <label htmlFor="name" className="mb-1.5 block text-sm font-medium text-slate-700">
            Club name *
          </label>
          <input
            id="name"
            name="name"
            type="text"
            required
            minLength={2}
            maxLength={160}
            className="input-control"
            placeholder="e.g. Robotics Club"
            aria-describedby="club-name-hint"
          />
          <p id="club-name-hint" className="mt-1 text-xs text-slate-500">
            This is what students see in search, invites, and your workspace header.
          </p>
        </div>

        <details className="rounded-xl border border-slate-200 bg-slate-50/60 open:bg-slate-50/80">
          <summary className="cursor-pointer list-none px-4 py-3 text-sm font-semibold text-slate-900 [&::-webkit-details-marker]:hidden">
            Optional
            <span className="ml-2 text-xs font-medium text-slate-500">Add a one-sentence purpose</span>
          </summary>
          <div className="border-t border-slate-200 px-4 py-4">
            <label htmlFor="tagline" className="mb-1.5 block text-sm font-medium text-slate-700">
              One-sentence purpose
            </label>
            <input
              id="tagline"
              name="tagline"
              type="text"
              className="input-control"
              placeholder="e.g. Build and race student-designed robots."
              maxLength={160}
            />
            <p className="mt-1 text-xs text-slate-500">
              Optional. You can write a longer description in Settings anytime.
            </p>
          </div>
        </details>

        <FormDraftPersistence
          formId="create-club-form"
          storageKey="clubhub:draft:create-club"
          fields={["name", "tagline"]}
          className="pt-1"
        />

        <button type="submit" className="btn-primary w-full sm:w-auto">
          Create club
        </button>
      </form>

      <p className="mt-6 text-sm text-slate-600">
        Want to join instead?{" "}
        <Link href="/clubs/join" className="font-semibold text-slate-900 hover:text-slate-700">
          Join a club
        </Link>
      </p>
    </section>
  );
}
