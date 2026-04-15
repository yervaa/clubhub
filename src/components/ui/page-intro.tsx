import type { ReactNode } from "react";

type PageIntroProps = {
  title: string;
  description: string;
  kicker?: string;
  actions?: ReactNode;
};

export function PageIntro({ title, description, kicker, actions }: PageIntroProps) {
  return (
    <header className="card-surface border border-slate-200/90 bg-gradient-to-br from-white to-slate-50/90 p-4 shadow-sm sm:p-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="max-w-3xl">
          {kicker ? <p className="section-kicker text-slate-600">{kicker}</p> : null}
          <h1 className="section-title mt-1 text-2xl sm:text-3xl">{title}</h1>
          <p className="section-subtitle mt-2 text-sm text-slate-600 sm:text-base">{description}</p>
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}
