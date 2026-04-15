type PageLoadingSkeletonProps = {
  withSidebarCards?: boolean;
};

export function PageLoadingSkeleton({ withSidebarCards = false }: PageLoadingSkeletonProps) {
  return (
    <section className="space-y-4 lg:space-y-6" aria-hidden>
      <div className="card-surface p-4 sm:p-5">
        <div className="skeleton skeleton-text h-3 w-20" />
        <div className="skeleton skeleton-text mt-3 h-8 w-48 sm:w-64" />
        <div className="skeleton skeleton-text mt-3 h-4 w-full max-w-xl" />
      </div>

      <div className={`grid gap-4 ${withSidebarCards ? "xl:grid-cols-2" : ""}`}>
        <div className="card-surface p-4 sm:p-5">
          <div className="skeleton skeleton-text h-3 w-24" />
          <div className="skeleton skeleton-text mt-3 h-5 w-44" />
          <div className="mt-4 space-y-2.5">
            <div className="skeleton skeleton-block h-16" />
            <div className="skeleton skeleton-block h-16" />
            <div className="skeleton skeleton-block h-16" />
          </div>
        </div>

        {withSidebarCards ? (
          <div className="card-surface p-4 sm:p-5">
            <div className="skeleton skeleton-text h-3 w-24" />
            <div className="skeleton skeleton-text mt-3 h-5 w-40" />
            <div className="mt-4 space-y-2.5">
              <div className="skeleton skeleton-block h-14" />
              <div className="skeleton skeleton-block h-14" />
              <div className="skeleton skeleton-block h-14" />
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}
