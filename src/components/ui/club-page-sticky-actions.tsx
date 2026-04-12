"use client";

type ClubPageStickyActionsProps = {
  href: string;
  label: string;
  visible: boolean;
};

/**
 * Mobile: fixed bottom primary CTA. Desktop (lg+): compact sticky top bar with the same action.
 */
export function ClubPageStickyActions({ href, label, visible }: ClubPageStickyActionsProps) {
  if (!visible) return null;

  return (
    <>
      <div
        className="fixed inset-x-0 bottom-0 z-40 border-t border-slate-200/90 bg-white/95 p-3 shadow-[0_-6px_24px_rgba(15,23,42,0.08)] backdrop-blur-sm lg:hidden"
        style={{ paddingBottom: "max(0.75rem, env(safe-area-inset-bottom))" }}
      >
        <a href={href} className="btn-primary flex min-h-11 w-full items-center justify-center px-4 py-3 text-center text-sm font-semibold">
          {label}
        </a>
      </div>
      <div className="sticky top-0 z-30 -mx-1 mb-3 hidden items-center justify-end gap-2 border-b border-slate-200/70 bg-gradient-to-b from-slate-50/98 to-slate-50/80 px-3 py-2.5 backdrop-blur-sm lg:flex">
        <a href={href} className="btn-primary px-4 py-2 text-sm font-semibold">
          {label}
        </a>
      </div>
    </>
  );
}
