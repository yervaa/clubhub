"use client";

import { useActionState } from "react";
import {
  changePasswordAction,
  updateDisplayNameAction,
  type ProfileActionState,
} from "@/app/(app)/settings/actions";
import { getMemberRosterInitials } from "@/lib/member-display";

type ProfileSettingsFormProps = {
  email: string;
  fullName: string;
};

function ActionMessage({ state }: { state: ProfileActionState }) {
  if (state?.ok === true && state.message) {
    return <p className="text-sm text-emerald-700">{state.message}</p>;
  }
  if (state?.ok === false) {
    return <p className="text-sm text-red-600">{state.message}</p>;
  }
  return null;
}

export function ProfileSettingsForm({ email, fullName }: ProfileSettingsFormProps) {
  const [nameState, nameAction, namePending] = useActionState(updateDisplayNameAction, null as ProfileActionState);
  const [passwordState, passwordAction, passwordPending] = useActionState(
    changePasswordAction,
    null as ProfileActionState,
  );

  const initials = getMemberRosterInitials({
    fullName: fullName || null,
    email,
  });

  return (
    <div className="mt-4 space-y-8">
      <div className="flex items-start gap-4 rounded-lg border border-slate-200 bg-slate-50/80 p-4">
        <div className="member-avatar is-current-user flex h-14 w-14 shrink-0 items-center justify-center text-lg">
          {initials}
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-slate-900">Profile photo</p>
          <p className="mt-1 text-xs leading-relaxed text-slate-600">
            Avatar uploads are not available yet — there is no profile-photos storage bucket in the database
            migrations (only <code className="rounded bg-slate-200/80 px-1 py-0.5 text-[11px]">announcement-attachments</code>
            ). Members are shown by initials across Clubora.
          </p>
        </div>
      </div>

      <form action={nameAction} className="space-y-4 border-t border-slate-100 pt-6">
        <p className="text-sm font-medium text-slate-900">Display name</p>
        <p className="text-xs text-slate-500">
          Shown on rosters, tasks, and activity. Stored in your profile and synced to your account metadata.
        </p>
        <div>
          <label htmlFor="profile-full-name" className="mb-1.5 block text-sm font-medium text-slate-700">
            Full name
          </label>
          <input
            id="profile-full-name"
            name="full_name"
            type="text"
            required
            minLength={2}
            maxLength={80}
            defaultValue={fullName}
            className="input-control max-w-md"
            autoComplete="name"
          />
        </div>
        <div>
          <label htmlFor="profile-email" className="mb-1.5 block text-sm font-medium text-slate-700">
            Email
          </label>
          <input
            id="profile-email"
            type="email"
            value={email}
            readOnly
            disabled
            className="input-control max-w-md cursor-not-allowed bg-slate-100 text-slate-600"
          />
          <p className="mt-1 text-xs text-slate-500">Email is managed through your sign-in account and cannot be changed here.</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="submit"
            disabled={namePending}
            className="inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-slate-800 disabled:opacity-60"
          >
            {namePending ? "Saving…" : "Save display name"}
          </button>
          <ActionMessage state={nameState} />
        </div>
      </form>

      <form action={passwordAction} className="space-y-4 border-t border-slate-100 pt-6">
        <p className="text-sm font-medium text-slate-900">Password</p>
        <p className="text-xs text-slate-500">
          Enter your current password to confirm, then choose a new one (at least 6 characters).
        </p>
        <div className="grid max-w-md gap-4">
          <div>
            <label htmlFor="current-password" className="mb-1.5 block text-sm font-medium text-slate-700">
              Current password
            </label>
            <input
              id="current-password"
              name="current_password"
              type="password"
              required
              minLength={6}
              autoComplete="current-password"
              className="input-control w-full"
            />
          </div>
          <div>
            <label htmlFor="new-password" className="mb-1.5 block text-sm font-medium text-slate-700">
              New password
            </label>
            <input
              id="new-password"
              name="new_password"
              type="password"
              required
              minLength={6}
              autoComplete="new-password"
              className="input-control w-full"
            />
          </div>
          <div>
            <label htmlFor="confirm-password" className="mb-1.5 block text-sm font-medium text-slate-700">
              Confirm new password
            </label>
            <input
              id="confirm-password"
              name="confirm_password"
              type="password"
              required
              minLength={6}
              autoComplete="new-password"
              className="input-control w-full"
            />
          </div>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="submit"
            disabled={passwordPending}
            className="inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-slate-800 disabled:opacity-60"
          >
            {passwordPending ? "Updating…" : "Change password"}
          </button>
          <ActionMessage state={passwordState} />
        </div>
      </form>
    </div>
  );
}
