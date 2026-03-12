import Link from "next/link";
import { createClubAction } from "@/app/(app)/clubs/actions";

type CreateClubPageProps = {
  searchParams: Promise<{ error?: string }>;
};

export default async function CreateClubPage({ searchParams }: CreateClubPageProps) {
  const params = await searchParams;

  return (
    <section className="card-surface max-w-2xl p-8">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Club Setup</p>
      <h1 className="section-title mt-2">Create Club</h1>
      <p className="section-subtitle">Start a club and instantly get a join code for members.</p>

      {params.error ? <p className="alert-error mt-6">{params.error}</p> : null}

      <form action={createClubAction} className="mt-7 space-y-4">
        <div>
          <label htmlFor="name" className="mb-1.5 block text-sm font-medium text-slate-700">
            Club name
          </label>
          <input id="name" name="name" type="text" required className="input-control" placeholder="e.g. Robotics Club" />
        </div>

        <div>
          <label htmlFor="description" className="mb-1.5 block text-sm font-medium text-slate-700">
            Description
          </label>
          <textarea id="description" name="description" required rows={4} className="textarea-control" placeholder="What does your club do?" />
        </div>

        <button type="submit" className="btn-primary">
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
