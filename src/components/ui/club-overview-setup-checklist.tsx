import Link from "next/link";
import type { ReactNode } from "react";

export type ClubSetupStep = {
  id: string;
  phase: "activation" | "optimization";
  title: string;
  description: string;
  done: boolean;
  href: string;
  cta: string;
  optional?: boolean;
};

type ClubOverviewSetupChecklistProps = {
  setupPercent: number;
  activationSteps: ClubSetupStep[];
  optimizationSteps: ClubSetupStep[];
  nextRecommendedStep: ClubSetupStep | undefined;
};

function SetupStepList({
  steps,
  nextRecommendedStep,
  nextBadgeClass,
  nextBorderClass,
}: {
  steps: ClubSetupStep[];
  nextRecommendedStep: ClubSetupStep | undefined;
  nextBadgeClass: string;
  nextBorderClass: string;
}) {
  return (
    <ul className="space-y-2">
      {steps.map((step) => {
        const isNext = nextRecommendedStep?.id === step.id;
        return (
          <li
            key={step.id}
            className={`flex items-start justify-between gap-3 rounded-lg border px-3 py-2.5 transition-colors ${
              isNext ? nextBorderClass : "border-slate-200 bg-white/90"
            }`}
          >
            <div className="min-w-0">
              <p className={`text-sm font-semibold ${step.done ? "text-slate-500 line-through" : "text-slate-900"}`}>
                {step.title}
                {step.optional ? (
                  <span className="ml-2 rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-slate-500">
                    Optional
                  </span>
                ) : null}
                {isNext && !step.done ? (
                  <span className={`ml-2 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${nextBadgeClass}`}>
                    Next
                  </span>
                ) : null}
              </p>
              <p className="mt-0.5 text-xs text-slate-600">{step.description}</p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {step.done ? (
                <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800">Done</span>
              ) : null}
              <Link href={step.href} className={step.done ? "btn-secondary text-xs" : "btn-primary text-xs"}>
                {step.done ? (step.phase === "optimization" ? "Edit" : "Review") : step.cta}
              </Link>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function ClubOverviewSetupChecklist({
  setupPercent,
  activationSteps,
  optimizationSteps,
  nextRecommendedStep,
}: ClubOverviewSetupChecklistProps) {
  const collapseByDefault = setupPercent >= 75;

  const checklistContent: ReactNode = (
    <>
      <div className="rounded-xl border border-violet-200 bg-violet-50/40 p-3 sm:p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-violet-700">Phase 1 - Activation</p>
        <p className="mt-1 text-sm text-slate-700">Most important first: activate your club with members, events, and communication.</p>
        <div className="mt-3">
          <SetupStepList
            steps={activationSteps}
            nextRecommendedStep={nextRecommendedStep}
            nextBadgeClass="bg-violet-100 text-violet-700"
            nextBorderClass="border-violet-300 bg-white"
          />
        </div>
      </div>

      <details className="rounded-xl border border-slate-200 bg-slate-50/60">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold text-slate-900 [&::-webkit-details-marker]:hidden">
          <span>Phase 2 - Optimization (optional depth)</span>
          <span className="text-xs font-medium text-slate-500">Skip for now</span>
        </summary>
        <div className="border-t border-slate-200 px-3 py-3 sm:px-4">
          <SetupStepList
            steps={optimizationSteps}
            nextRecommendedStep={nextRecommendedStep}
            nextBadgeClass="bg-blue-100 text-blue-700"
            nextBorderClass="border-blue-300 bg-white"
          />
        </div>
      </details>
    </>
  );

  return (
    <>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-100">
        <div
          className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-[width] duration-300"
          style={{ width: `${setupPercent}%` }}
        />
      </div>
      {collapseByDefault ? (
        <details className="mt-4 group">
          <summary className="club-overview-setup-checklist__summary cursor-pointer list-none text-sm font-semibold text-slate-700 [&::-webkit-details-marker]:hidden">
            Review setup steps
          </summary>
          <div className="mt-4 space-y-3">{checklistContent}</div>
        </details>
      ) : (
        <div className="mt-4 space-y-3">{checklistContent}</div>
      )}
    </>
  );
}
