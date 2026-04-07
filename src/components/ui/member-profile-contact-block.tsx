"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import {
  getClubMemberContactAction,
  upsertClubMemberContactAction,
  type ClubMemberContactView,
} from "@/app/(app)/clubs/member-contact-actions";

function formatPreference(
  m: ClubMemberContactView["preferredContactMethod"],
): string {
  if (m === "email") return "Email";
  if (m === "phone") return "Phone";
  if (m === "either") return "Email or phone";
  return "—";
}

type MemberProfileContactBlockProps = {
  clubId: string;
  memberUserId: string;
  dialogOpen: boolean;
  /** Load from server (self always; others only when leadership). */
  shouldFetch: boolean;
  /** Show edit form (active self, club not archived). */
  canEdit: boolean;
  /** Explains read-only state for your own profile when marked alumni. */
  isAlumniSelf?: boolean;
};

export function MemberProfileContactBlock({
  clubId,
  memberUserId,
  dialogOpen,
  shouldFetch,
  canEdit,
  isAlumniSelf = false,
}: MemberProfileContactBlockProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [contact, setContact] = useState<ClubMemberContactView | null | undefined>(undefined);
  const [phone, setPhone] = useState("");
  const [preference, setPreference] = useState<"" | "email" | "phone" | "either">("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!dialogOpen || !shouldFetch) {
      setContact(undefined);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    (async () => {
      const r = await getClubMemberContactAction(clubId, memberUserId);
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) {
        setError(r.error);
        setContact(null);
        return;
      }
      const c = r.contact;
      setContact(c);
      setPhone(c?.phoneNumber ?? "");
      setPreference(c?.preferredContactMethod ?? "");
    })();

    return () => {
      cancelled = true;
    };
  }, [dialogOpen, shouldFetch, clubId, memberUserId]);

  if (!shouldFetch) {
    return null;
  }

  return (
    <section className="rounded-xl border border-slate-200/90 bg-slate-50/50 p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-600">Club contact (optional)</h3>
      <p className="mt-1 text-xs leading-relaxed text-slate-600">
        Phone and how you prefer to be reached <span className="font-semibold">for this club only</span>. Not shown on the
        main roster list or roster export. Leadership can open profiles to view what members choose to share.
      </p>

      {loading || contact === undefined ? (
        <p className="mt-3 text-sm text-slate-500">Loading…</p>
      ) : error ? (
        <p className="mt-3 text-sm text-red-800" role="alert">
          {error}
        </p>
      ) : canEdit ? (
        <form
          className="mt-4 space-y-3"
          onSubmit={async (e) => {
            e.preventDefault();
            setSaving(true);
            setError(null);
            const r = await upsertClubMemberContactAction({
              clubId,
              phoneNumber: phone,
              preferredContactMethod: preference === "" ? null : preference,
            });
            setSaving(false);
            if (!r.ok) {
              setError(r.error);
              return;
            }
            const refreshed = await getClubMemberContactAction(clubId, memberUserId);
            if (refreshed.ok) {
              setContact(refreshed.contact);
              setPhone(refreshed.contact?.phoneNumber ?? "");
              setPreference(refreshed.contact?.preferredContactMethod ?? "");
            }
            router.refresh();
          }}
        >
          <div>
            <label htmlFor={`club-contact-phone-${memberUserId}`} className="mb-1 block text-xs font-semibold text-slate-700">
              Mobile / phone
            </label>
            <input
              id={`club-contact-phone-${memberUserId}`}
              type="text"
              inputMode="tel"
              autoComplete="tel"
              maxLength={40}
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              className="input-control w-full max-w-md text-sm"
              placeholder="Optional"
            />
          </div>
          <div>
            <label htmlFor={`club-contact-pref-${memberUserId}`} className="mb-1 block text-xs font-semibold text-slate-700">
              Preferred for club messages
            </label>
            <select
              id={`club-contact-pref-${memberUserId}`}
              value={preference}
              onChange={(e) => setPreference(e.target.value as typeof preference)}
              className="input-control w-full max-w-md text-sm"
            >
              <option value="">No preference set</option>
              <option value="email">Email</option>
              <option value="phone">Phone</option>
              <option value="either">Email or phone</option>
            </select>
          </div>
          {error ? (
            <p className="text-sm text-red-800" role="alert">
              {error}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <button type="submit" className="btn-primary px-4 py-2 text-sm font-semibold" disabled={saving}>
              {saving ? "Saving…" : "Save club contact"}
            </button>
          </div>
        </form>
      ) : (
        <div className="mt-3 text-sm text-slate-800">
          {isAlumniSelf ? (
            <p className="mb-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-950">
              Alumni memberships cannot update club contact here. Ask leadership if something needs changing.
            </p>
          ) : null}
          {!contact?.phoneNumber && !contact?.preferredContactMethod ? (
            <p className="text-slate-600">No optional club contact on file.</p>
          ) : (
            <dl className="space-y-2">
              {contact.phoneNumber ? (
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Phone</dt>
                  <dd className="mt-0.5 font-mono text-sm">{contact.phoneNumber}</dd>
                </div>
              ) : null}
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Preference</dt>
                <dd className="mt-0.5 text-sm">{formatPreference(contact?.preferredContactMethod ?? null)}</dd>
              </div>
            </dl>
          )}
          <p className="mt-3 text-xs text-slate-500">
            Members manage this themselves. School sign-in email is separate (shown only on your own profile).
          </p>
        </div>
      )}
    </section>
  );
}
