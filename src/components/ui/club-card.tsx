import Link from "next/link";
import type { MockClub } from "@/lib/mock-data";

type ClubCardProps = {
  club: MockClub;
};

export function ClubCard({ club }: ClubCardProps) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-base font-semibold text-slate-900">{club.name}</h3>
        <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700">
          {club.role}
        </span>
      </div>
      <p className="mt-2 text-sm text-slate-600">{club.description}</p>
      <div className="mt-4 flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-[0.08em] text-slate-500">
          {club.memberCount} members
        </p>
        <Link
          href={`/clubs/${club.slug}`}
          className="text-sm font-semibold text-slate-900 hover:text-slate-700"
        >
          View club
        </Link>
      </div>
    </article>
  );
}
