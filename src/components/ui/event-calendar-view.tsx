"use client";

import { useState, useMemo } from "react";
import Link from "next/link";

type CalendarEvent = {
  id: string;
  title: string;
  eventType: string;
  eventDateIso: string;
  rsvpStatus: string | null;
};

type EventCalendarViewProps = {
  events: CalendarEvent[];
  clubId: string;
};

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

const TYPE_COLORS: Record<string, string> = {
  Meeting: "bg-blue-500",
  Workshop: "bg-violet-500",
  Social: "bg-emerald-500",
  Competition: "bg-amber-500",
  Fundraiser: "bg-pink-500",
  Service: "bg-teal-500",
  Other: "bg-slate-500",
};

export function EventCalendarView({ events, clubId }: EventCalendarViewProps) {
  const today = new Date();
  const [viewYear, setViewYear] = useState(today.getFullYear());
  const [viewMonth, setViewMonth] = useState(today.getMonth());

  const calendarDays = useMemo(() => {
    const firstOfMonth = new Date(viewYear, viewMonth, 1);
    const lastOfMonth = new Date(viewYear, viewMonth + 1, 0);
    const startDay = firstOfMonth.getDay();

    const days: Array<{ date: Date; isCurrentMonth: boolean }> = [];

    // Fill leading days from previous month.
    for (let i = startDay - 1; i >= 0; i--) {
      const d = new Date(viewYear, viewMonth, -i);
      days.push({ date: d, isCurrentMonth: false });
    }

    // Days in month.
    for (let d = 1; d <= lastOfMonth.getDate(); d++) {
      days.push({ date: new Date(viewYear, viewMonth, d), isCurrentMonth: true });
    }

    // Fill trailing days to complete the grid (always show 6 rows).
    const remaining = 42 - days.length;
    for (let d = 1; d <= remaining; d++) {
      days.push({ date: new Date(viewYear, viewMonth + 1, d), isCurrentMonth: false });
    }

    return days;
  }, [viewYear, viewMonth]);

  const eventsByDay = useMemo(() => {
    const map = new Map<string, CalendarEvent[]>();
    for (const ev of events) {
      const d = new Date(ev.eventDateIso);
      const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
      const existing = map.get(key) ?? [];
      existing.push(ev);
      map.set(key, existing);
    }
    return map;
  }, [events]);

  function prev() {
    if (viewMonth === 0) { setViewYear((y) => y - 1); setViewMonth(11); }
    else setViewMonth((m) => m - 1);
  }

  function next() {
    if (viewMonth === 11) { setViewYear((y) => y + 1); setViewMonth(0); }
    else setViewMonth((m) => m + 1);
  }

  function goToday() {
    setViewYear(today.getFullYear());
    setViewMonth(today.getMonth());
  }

  return (
    <div className="card-surface overflow-hidden">
      {/* Calendar header */}
      <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
        <h2 className="text-base font-bold text-slate-900">
          {MONTHS[viewMonth]} {viewYear}
        </h2>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={goToday}
            className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-semibold text-slate-600 transition hover:bg-slate-50"
          >
            Today
          </button>
          <button type="button" onClick={prev} className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:bg-slate-50">
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
          </button>
          <button type="button" onClick={next} className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:bg-slate-50">
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
          </button>
        </div>
      </div>

      {/* Weekday headers */}
      <div className="grid grid-cols-7 border-b border-slate-100 bg-slate-50/50">
        {WEEKDAYS.map((day) => (
          <div key={day} className="py-2 text-center text-[11px] font-bold uppercase tracking-wider text-slate-400">
            {day}
          </div>
        ))}
      </div>

      {/* Calendar grid */}
      <div className="grid grid-cols-7">
        {calendarDays.map(({ date, isCurrentMonth }, idx) => {
          const isToday = sameDay(date, today);
          const key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
          const dayEvents = eventsByDay.get(key) ?? [];

          return (
            <div
              key={idx}
              className={`min-h-[4.5rem] border-b border-r border-slate-100 px-1.5 py-1.5 sm:min-h-[5.5rem] sm:px-2 ${
                !isCurrentMonth ? "bg-slate-50/40" : ""
              }`}
            >
              <span
                className={`inline-flex h-6 w-6 items-center justify-center rounded-full text-xs font-semibold ${
                  isToday
                    ? "bg-slate-900 text-white"
                    : isCurrentMonth
                    ? "text-slate-700"
                    : "text-slate-300"
                }`}
              >
                {date.getDate()}
              </span>
              {dayEvents.length > 0 && (
                <div className="mt-0.5 space-y-0.5">
                  {dayEvents.slice(0, 2).map((ev) => (
                    <Link
                      key={ev.id}
                      href={`/clubs/${clubId}/events`}
                      className={`block truncate rounded px-1 py-0.5 text-[10px] font-semibold leading-tight text-white transition hover:opacity-80 sm:text-[11px] ${TYPE_COLORS[ev.eventType] ?? "bg-slate-500"}`}
                      title={ev.title}
                    >
                      {ev.title}
                    </Link>
                  ))}
                  {dayEvents.length > 2 && (
                    <p className="px-1 text-[10px] font-medium text-slate-400">
                      +{dayEvents.length - 2} more
                    </p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
