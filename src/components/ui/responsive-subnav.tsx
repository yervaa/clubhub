"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

export type ResponsiveSubnavItem = {
  label: string;
  href: string;
  active: boolean;
};

type ResponsiveSubnavProps = {
  items: ResponsiveSubnavItem[];
  ariaLabel: string;
  pickerLabel: string;
};

export function ResponsiveSubnav({ items, ariaLabel, pickerLabel }: ResponsiveSubnavProps) {
  const router = useRouter();
  const currentHref = items.find((item) => item.active)?.href ?? items[0]?.href ?? "";

  if (items.length === 0) return null;

  return (
    <nav aria-label={ariaLabel} className="space-y-2">
      <div className="lg:hidden">
        <label htmlFor={`${pickerLabel}-picker`} className="sr-only">
          {pickerLabel}
        </label>
        <select
          id={`${pickerLabel}-picker`}
          value={currentHref}
          onChange={(e) => router.push(e.target.value)}
          className="w-full rounded-xl border border-slate-200 bg-white py-3 pl-3 pr-10 text-sm font-semibold text-slate-800 shadow-sm focus:border-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-200"
        >
          {items.map((item) => (
            <option key={item.href} value={item.href}>
              {item.label}
            </option>
          ))}
        </select>
      </div>

      <div className="hidden gap-1 rounded-xl border border-slate-200 bg-slate-50 p-1 lg:flex">
        {items.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            aria-current={item.active ? "page" : undefined}
            className={`flex-1 rounded-lg px-4 py-2 text-center text-sm font-semibold transition-all ${
              item.active ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:bg-white/60 hover:text-slate-700"
            }`}
          >
            {item.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
