import Link from "next/link";
import { Navbar } from "@/components/layout/navbar";
import { mockClubs } from "@/lib/mock-data";

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto flex w-full max-w-6xl flex-col px-4 py-16 sm:px-6 sm:py-24">
        <div className="max-w-3xl">
          <span className="inline-flex rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-slate-600">
            ClubHub MVP
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight text-slate-900 sm:text-5xl">
            One place for your school clubs to run everything.
          </h1>
          <p className="mt-4 text-lg text-slate-600">
            ClubHub centralizes announcements, events, and member engagement so officers and students can stay in sync.
          </p>
        </div>

        <div className="mt-8 flex flex-col gap-3 sm:flex-row">
          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center rounded-md bg-slate-900 px-5 py-3 text-sm font-semibold text-white transition hover:bg-slate-700"
          >
            Open Dashboard Shell
          </Link>
          <Link
            href="/signup"
            className="inline-flex items-center justify-center rounded-md border border-slate-300 bg-white px-5 py-3 text-sm font-semibold text-slate-800 transition hover:border-slate-400 hover:bg-slate-100"
          >
            Create Account
          </Link>
        </div>

        <div className="mt-12 grid gap-4 md:grid-cols-3">
          <article className="rounded-xl border border-slate-200 bg-white p-5">
            <h2 className="text-sm font-semibold text-slate-900">Announcements</h2>
            <p className="mt-2 text-sm text-slate-600">Post updates for every club member in one stream.</p>
          </article>
          <article className="rounded-xl border border-slate-200 bg-white p-5">
            <h2 className="text-sm font-semibold text-slate-900">Events + RSVP</h2>
            <p className="mt-2 text-sm text-slate-600">Create events quickly and track who plans to attend.</p>
          </article>
          <article className="rounded-xl border border-slate-200 bg-white p-5">
            <h2 className="text-sm font-semibold text-slate-900">Club Dashboard</h2>
            <p className="mt-2 text-sm text-slate-600">View your clubs, latest updates, and upcoming activities.</p>
          </article>
        </div>

        <section className="mt-12">
          <h2 className="text-lg font-semibold tracking-tight text-slate-900">Sample Clubs in the MVP</h2>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            {mockClubs.map((club) => (
              <article key={club.id} className="rounded-xl border border-slate-200 bg-white p-5">
                <h3 className="text-sm font-semibold text-slate-900">{club.name}</h3>
                <p className="mt-2 text-sm text-slate-600">{club.description}</p>
                <Link
                  href="/dashboard"
                  className="mt-4 inline-flex text-sm font-semibold text-slate-900 hover:text-slate-700"
                >
                  Open dashboard
                </Link>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
