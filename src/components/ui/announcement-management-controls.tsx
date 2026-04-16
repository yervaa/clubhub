"use client";

import { useFormStatus } from "react-dom";
import { deleteAnnouncementAction, updateAnnouncementAction } from "@/app/(app)/clubs/actions";

type AnnouncementManagementControlsProps = {
  clubId: string;
  announcementId: string;
  title: string;
  content: string;
  isPublished: boolean;
  isPinned: boolean;
  isUrgent: boolean;
  canEdit: boolean;
  canDelete: boolean;
};

function SaveAnnouncementButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-secondary min-h-10 text-xs" disabled={pending}>
      {pending ? "Saving..." : label}
    </button>
  );
}

function DeleteAnnouncementButton() {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      className="btn-danger min-h-10 text-xs"
      disabled={pending}
      onClick={(event) => {
        if (!window.confirm("Delete this announcement? This also removes its read and poll records.")) {
          event.preventDefault();
        }
      }}
    >
      {pending ? "Deleting..." : "Delete"}
    </button>
  );
}

export function AnnouncementManagementControls({
  clubId,
  announcementId,
  title,
  content,
  isPublished,
  isPinned,
  isUrgent,
  canEdit,
  canDelete,
}: AnnouncementManagementControlsProps) {
  if (!canEdit && !canDelete) return null;

  return (
    <div className="mt-4 space-y-3 border-t border-slate-100 pt-3">
      {canEdit ? (
        <details className="rounded-lg border border-slate-200 bg-slate-50/70">
          <summary className="cursor-pointer list-none px-3 py-2 text-xs font-semibold text-slate-900 [&::-webkit-details-marker]:hidden">
            Manage announcement
          </summary>
          <form action={updateAnnouncementAction} className="space-y-3 border-t border-slate-200 px-3 py-3">
            <input type="hidden" name="club_id" value={clubId} />
            <input type="hidden" name="announcement_id" value={announcementId} />
            <div>
              <label htmlFor={`ann-title-edit-${announcementId}`} className="mb-1 block text-xs font-medium text-slate-700">
                Title
              </label>
              <input
                id={`ann-title-edit-${announcementId}`}
                name="title"
                type="text"
                required
                minLength={3}
                maxLength={160}
                defaultValue={title}
                className="input-control min-h-10"
              />
            </div>
            <div>
              <label htmlFor={`ann-content-edit-${announcementId}`} className="mb-1 block text-xs font-medium text-slate-700">
                Message
              </label>
              <textarea
                id={`ann-content-edit-${announcementId}`}
                name="content"
                required
                minLength={6}
                maxLength={2000}
                rows={4}
                defaultValue={content}
                className="textarea-control"
              />
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <label className="flex items-center gap-2 rounded-md border border-slate-200 bg-white px-2 py-2 text-xs text-slate-700">
                <input type="checkbox" name="is_urgent" defaultChecked={isUrgent} />
                Mark as urgent
              </label>
              <label className="flex items-center gap-2 rounded-md border border-slate-200 bg-white px-2 py-2 text-xs text-slate-700">
                <input type="checkbox" name="is_pinned" defaultChecked={isPinned} />
                Pin announcement
              </label>
            </div>

            <div className="flex flex-wrap gap-2">
              <input type="hidden" name="announcement_intent" value="save_changes" />
              <SaveAnnouncementButton label={isPublished ? "Save changes" : "Update draft"} />
              {!isPublished ? (
                <button
                  type="submit"
                  className="btn-primary min-h-10 text-xs"
                  name="announcement_intent"
                  value="publish_now"
                >
                  Publish draft
                </button>
              ) : null}
            </div>
          </form>
        </details>
      ) : null}

      {canDelete ? (
        <form action={deleteAnnouncementAction}>
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="announcement_id" value={announcementId} />
          <DeleteAnnouncementButton />
        </form>
      ) : null}
    </div>
  );
}
