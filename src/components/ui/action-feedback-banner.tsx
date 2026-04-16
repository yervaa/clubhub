import type { ReactNode } from "react";

type ActionFeedbackBannerProps = {
  variant: "success" | "error";
  title: string;
  message?: string;
  actions?: ReactNode;
  className?: string;
};

export function ActionFeedbackBanner({
  variant,
  title,
  message,
  actions,
  className = "",
}: ActionFeedbackBannerProps) {
  const base =
    variant === "success"
      ? "rounded-xl border border-emerald-200 bg-emerald-50/80 text-emerald-950"
      : "rounded-xl border border-rose-200 bg-rose-50/80 text-rose-950";

  return (
    <div className={`${base} px-4 py-3 ${className}`.trim()} role="status" aria-live="polite">
      <p className="text-sm font-semibold">{title}</p>
      {message ? <p className="mt-1 text-sm opacity-90">{message}</p> : null}
      {actions ? <div className="mt-3 flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}
