"use client";

import { useActionState } from "react";
import {
  updateNotificationPreferencesAction,
  type NotificationPreferencesActionState,
} from "@/app/(app)/settings/actions";
import type { NotificationPreferencesRow } from "@/lib/notifications/preference-model";

const COMMON_TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Phoenix",
  "America/Toronto",
  "America/Vancouver",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Singapore",
  "Asia/Dubai",
  "Australia/Sydney",
  "Pacific/Auckland",
] as const;

type Props = {
  defaults: Omit<NotificationPreferencesRow, "user_id">;
};

function ToggleRow({
  label,
  description,
  inAppName,
  emailName,
  inAppDefault,
  emailDefault,
}: {
  label: string;
  description?: string;
  inAppName: string;
  emailName: string;
  inAppDefault: boolean;
  emailDefault: boolean;
}) {
  return (
    <div className="flex flex-col gap-2 border-b border-slate-100 py-3 last:border-b-0 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="text-sm font-medium text-slate-900">{label}</p>
        {description ? <p className="mt-0.5 text-xs text-slate-500">{description}</p> : null}
      </div>
      <div className="flex flex-wrap gap-4 text-sm">
        <label className="inline-flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            name={inAppName}
            defaultChecked={inAppDefault}
            className="size-4 rounded border-slate-300 text-slate-900"
          />
          <span className="text-slate-700">In-app</span>
        </label>
        <label className="inline-flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            name={emailName}
            defaultChecked={emailDefault}
            className="size-4 rounded border-slate-300 text-slate-900"
          />
          <span className="text-slate-700">Email</span>
        </label>
      </div>
    </div>
  );
}

export function NotificationSettingsForm({ defaults }: Props) {
  const [state, formAction, isPending] = useActionState(
    updateNotificationPreferencesAction,
    null as NotificationPreferencesActionState,
  );

  const quietDefault = defaults.quiet_hours_enabled;
  const startDefault = defaults.quiet_hours_start ?? "22:00";
  const endDefault = defaults.quiet_hours_end ?? "07:00";

  return (
    <form action={formAction} className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-900">In-app & email by category</p>
        <p className="mt-1 text-xs text-slate-500">
          In-app alerts appear in your notification list. Email sends immediately outside quiet hours (weekly digest
          is separate).
        </p>
        <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 sm:px-4">
          <ToggleRow
            label="Announcements & polls"
            inAppName="in_app_announcements"
            emailName="email_announcements"
            inAppDefault={defaults.in_app_announcements}
            emailDefault={defaults.email_announcements}
          />
          <ToggleRow
            label="Events & RSVPs"
            description="Event created, RSVP updates, attendance."
            inAppName="in_app_events"
            emailName="email_events"
            inAppDefault={defaults.in_app_events}
            emailDefault={defaults.email_events}
          />
          <ToggleRow
            label="Reminders"
            description="Scheduled event reminders."
            inAppName="in_app_reminders"
            emailName="email_reminders"
            inAppDefault={defaults.in_app_reminders}
            emailDefault={defaults.email_reminders}
          />
          <ToggleRow
            label="Roles & membership"
            description="Officer role changes and similar updates."
            inAppName="in_app_role_membership"
            emailName="email_role_membership"
            inAppDefault={defaults.in_app_role_membership}
            emailDefault={defaults.email_role_membership}
          />
          <ToggleRow
            label="Tasks & club activity"
            description="Task assignments and other activity notices."
            inAppName="in_app_activity"
            emailName="email_activity"
            inAppDefault={defaults.in_app_activity}
            emailDefault={defaults.email_activity}
          />
        </div>
      </div>

      <div>
        <p className="text-sm font-medium text-slate-900">Quiet hours (email only)</p>
        <p className="mt-1 text-xs text-slate-500">
          During quiet hours, immediate notification emails are not sent; in-app notifications are unchanged. Cross-midnight
          windows (e.g. 22:00–07:00) are supported.
        </p>
        <div className="mt-3 space-y-3 rounded-lg border border-slate-200 bg-slate-50/80 p-3 sm:p-4">
          <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              name="quiet_hours_enabled"
              defaultChecked={quietDefault}
              className="size-4 rounded border-slate-300 text-slate-900"
            />
            <span className="font-medium text-slate-800">Enable quiet hours</span>
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="text-slate-600">Start (local)</span>
              <input
                type="time"
                name="quiet_hours_start"
                defaultValue={startDefault}
                className="mt-1 w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm"
              />
            </label>
            <label className="block text-sm">
              <span className="text-slate-600">End (local)</span>
              <input
                type="time"
                name="quiet_hours_end"
                defaultValue={endDefault}
                className="mt-1 w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm"
              />
            </label>
          </div>
          <label className="block text-sm">
            <span className="text-slate-600">Timezone</span>
            <select
              name="timezone"
              defaultValue={defaults.timezone}
              className="mt-1 w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm"
            >
              {[...new Set([defaults.timezone, ...COMMON_TIMEZONES])].sort().map((tz) => (
                <option key={tz} value={tz}>
                  {tz}
                </option>
              ))}
            </select>
          </label>
          <p className="text-xs text-slate-500">
            Invalid timezones fall back to UTC when evaluating quiet hours.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-3 sm:p-4">
        <label className="flex cursor-pointer items-start gap-3 text-sm">
          <input
            type="checkbox"
            name="weekly_digest_enabled"
            defaultChecked={defaults.weekly_digest_enabled}
            className="mt-0.5 size-4 rounded border-slate-300 text-slate-900"
          />
          <span>
            <span className="font-medium text-slate-900">Weekly digest email</span>
            <span className="mt-1 block text-xs font-normal text-slate-500">
              One summary email with recent announcements and upcoming events across your clubs. Sent on the schedule
              your host configures (e.g. weekly cron).
            </span>
          </span>
        </label>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <button
          type="submit"
          disabled={isPending}
          className="inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-slate-800 disabled:opacity-60"
        >
          {isPending ? "Saving…" : "Save notification settings"}
        </button>
        {state?.ok === true && state.message ? (
          <p className="text-sm text-emerald-700">{state.message}</p>
        ) : null}
        {state?.ok === false ? <p className="text-sm text-red-600">{state.message}</p> : null}
      </div>
    </form>
  );
}
