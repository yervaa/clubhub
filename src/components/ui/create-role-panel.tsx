"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ROLE_TEMPLATES,
  ROLE_TEMPLATE_ORDER,
  type RoleTemplate,
  type RoleTemplateKey,
} from "@/lib/rbac/role-templates";
import { PERMISSION_CATALOG } from "@/lib/rbac/permission-catalog";
import { createCustomRoleAction } from "@/app/(app)/clubs/rbac-actions";

type CreateRolePanelProps = {
  clubId: string;
};

// ─── Main component ───────────────────────────────────────────────────────────

export function CreateRolePanel({ clubId }: CreateRolePanelProps) {
  const [selectedKey, setSelectedKey] = useState<RoleTemplateKey | null>(null);

  if (!selectedKey) {
    return <TemplatePicker clubId={clubId} onSelect={setSelectedKey} />;
  }

  return (
    <RoleForm
      clubId={clubId}
      template={ROLE_TEMPLATES[selectedKey]}
      onBack={() => setSelectedKey(null)}
    />
  );
}

// ─── Step 1: Template picker ──────────────────────────────────────────────────

function TemplatePicker({
  clubId,
  onSelect,
}: {
  clubId: string;
  onSelect: (key: RoleTemplateKey) => void;
}) {
  return (
    <div className="card-surface p-6 md:p-8">
      <div className="mb-6">
        <p className="section-kicker">New Role</p>
        <h2 className="section-title mt-2 text-xl">Choose a starting point</h2>
        <p className="section-subtitle mt-1">
          Pick a template to pre-fill common permissions, or start from scratch. You can change everything after creation.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {ROLE_TEMPLATE_ORDER.map((key) => {
          const template = ROLE_TEMPLATES[key];
          const isBlank = key === "blank";
          const permCount = template.permissions.length;

          return (
            <button
              key={key}
              type="button"
              onClick={() => onSelect(key)}
              className={`group flex w-full items-start gap-4 rounded-xl border p-4 text-left transition-all hover:border-slate-300 hover:shadow-sm active:scale-[0.99] ${
                isBlank
                  ? "border-dashed border-slate-200 hover:border-slate-300"
                  : "border-slate-200 hover:border-violet-200 hover:bg-violet-50/40"
              }`}
            >
              {/* Emoji icon */}
              <span
                className={`flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl text-xl ${
                  isBlank ? "bg-slate-100" : "bg-violet-50 group-hover:bg-violet-100"
                }`}
                aria-hidden
              >
                {template.emoji}
              </span>

              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-semibold text-slate-900">{template.name}</p>
                  {!isBlank && (
                    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-500">
                      {permCount} perm{permCount !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-xs leading-relaxed text-slate-500">{template.tagline}</p>
              </div>

              {/* Arrow */}
              <svg
                className="mt-1 h-4 w-4 flex-shrink-0 text-slate-300 transition-colors group-hover:text-violet-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
          );
        })}
      </div>

      <div className="mt-5 flex justify-start border-t border-slate-100 pt-5">
        <Link
          href={`/clubs/${clubId}/settings`}
          className="btn-secondary text-sm"
        >
          Cancel
        </Link>
      </div>
    </div>
  );
}

// ─── Step 2: Role creation form ───────────────────────────────────────────────

function RoleForm({
  clubId,
  template,
  onBack,
}: {
  clubId: string;
  template: RoleTemplate;
  onBack: () => void;
}) {
  const hasPermissions = template.permissions.length > 0;

  // Group permissions by category for the preview
  const permsByCategory = template.permissions.reduce<Record<string, string[]>>((acc, key) => {
    const cat = PERMISSION_CATALOG[key]?.category ?? "Other";
    (acc[cat] ??= []).push(PERMISSION_CATALOG[key]?.label ?? key);
    return acc;
  }, {});

  return (
    <div className="card-surface p-6 md:p-8">
      {/* Back button + header */}
      <div className="mb-6">
        <button
          type="button"
          onClick={onBack}
          className="mb-4 inline-flex items-center gap-1.5 text-sm font-medium text-slate-500 hover:text-slate-800 transition-colors"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to templates
        </button>

        <div className="flex items-center gap-3">
          <span
            className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-violet-50 text-xl"
            aria-hidden
          >
            {template.emoji}
          </span>
          <div>
            <p className="section-kicker">New Role · {template.name} template</p>
            <h2 className="section-title mt-0.5 text-xl">Configure your role</h2>
          </div>
        </div>
        <p className="section-subtitle mt-2">
          Adjust the name and description below. Permissions will be set after creation.
        </p>
      </div>

      <form action={createCustomRoleAction} className="space-y-5">
        <input type="hidden" name="club_id" value={clubId} />
        <input type="hidden" name="template_key" value={template.key} />

        {/* Name */}
        <div className="space-y-1.5">
          <label htmlFor="role-name" className="block text-sm font-semibold text-slate-700">
            Role name <span className="text-red-500">*</span>
          </label>
          <input
            id="role-name"
            name="name"
            type="text"
            required
            maxLength={50}
            defaultValue={template.key === "blank" ? "" : template.name}
            placeholder="e.g. Social Media Lead"
            className="input-control"
            autoFocus
          />
          <p className="text-xs text-slate-400">Max 50 characters.</p>
        </div>

        {/* Description */}
        <div className="space-y-1.5">
          <label htmlFor="role-desc" className="block text-sm font-semibold text-slate-700">
            Description
          </label>
          <input
            id="role-desc"
            name="description"
            type="text"
            maxLength={200}
            defaultValue={template.key === "blank" ? "" : template.description}
            placeholder="Short description of what this role does"
            className="input-control"
          />
          <p className="text-xs text-slate-400">Optional. Max 200 characters.</p>
        </div>

        {/* Permission preview */}
        {hasPermissions ? (
          <div className="rounded-xl border border-violet-100 bg-violet-50/60 p-4">
            <p className="mb-3 text-sm font-semibold text-violet-900">
              Starting with {template.permissions.length} permission{template.permissions.length !== 1 ? "s" : ""}
            </p>
            <div className="space-y-2">
              {Object.entries(permsByCategory).map(([cat, labels]) => (
                <div key={cat} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                  <span className="text-xs font-semibold uppercase tracking-wide text-violet-500 w-28 shrink-0">
                    {cat}
                  </span>
                  <span className="text-xs text-slate-600">
                    {labels.join(", ")}
                  </span>
                </div>
              ))}
            </div>
            <p className="mt-3 text-xs text-violet-600">
              You can adjust permissions from the role editor after creation.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
            <p className="text-sm text-slate-500">
              No permissions will be set initially. Configure them from the role editor after creation.
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="flex flex-col gap-3 border-t border-slate-100 pt-5 sm:flex-row sm:items-center">
          <button type="submit" className="btn-primary px-5 py-2.5">
            Create Role
          </button>
          <button
            type="button"
            onClick={onBack}
            className="btn-secondary px-5 py-2.5 text-center"
          >
            Back to Templates
          </button>
          <Link
            href={`/clubs/${clubId}/settings`}
            className="text-sm font-medium text-slate-400 hover:text-slate-600 transition-colors sm:ml-auto"
          >
            Cancel
          </Link>
        </div>
      </form>
    </div>
  );
}
