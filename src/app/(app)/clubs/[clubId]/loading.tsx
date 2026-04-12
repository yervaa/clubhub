export default function ClubSectionLoading() {
  return (
    <div className="space-y-4 animate-pulse lg:space-y-6" aria-hidden>
      <div className="h-10 rounded-xl bg-slate-200/80" />
      <div className="card-surface h-40 border border-slate-200/90 bg-slate-100/80 sm:h-48" />
      <div className="card-surface h-64 border border-slate-200/90 bg-slate-50/90" />
    </div>
  );
}
