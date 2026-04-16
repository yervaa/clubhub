"use client";

import { useEffect, useMemo, useState } from "react";

type FormDraftPersistenceProps = {
  formId: string;
  storageKey: string;
  fields: string[];
  successSignal?: string;
  className?: string;
};

function formatTime(ts: number | null): string {
  if (!ts) return "Draft autosaves on this device";
  return `Draft saved at ${new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

export function FormDraftPersistence({
  formId,
  storageKey,
  fields,
  successSignal,
  className = "",
}: FormDraftPersistenceProps) {
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [hasDraft, setHasDraft] = useState(false);
  const fieldSet = useMemo(() => new Set(fields), [fields]);

  useEffect(() => {
    const form = document.getElementById(formId) as HTMLFormElement | null;
    if (!form) return;

    const restoreDraft = () => {
      try {
        if (successSignal) {
          localStorage.removeItem(storageKey);
          return;
        }
        const raw = localStorage.getItem(storageKey);
        if (!raw) return;
        const parsed = JSON.parse(raw) as Record<string, string>;

        for (const name of fields) {
          const node = form.elements.namedItem(name);
          if (
            !node ||
            !(node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement || node instanceof HTMLSelectElement)
          ) {
            continue;
          }
          if (node.type === "file") continue;
          const value = parsed[name];
          if (typeof value !== "string" || value.length === 0) continue;
          if ((node.value ?? "").length > 0) continue;
          node.value = value;
        }
      } catch {
        /* ignore malformed storage payload */
      }
    };

    const persist = () => {
      const payload: Record<string, string> = {};
      let anyValue = false;

      for (const element of Array.from(form.elements)) {
        if (
          !(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement)
        ) {
          continue;
        }
        if (!fieldSet.has(element.name)) continue;
        if (element.type === "file") continue;
        payload[element.name] = element.value ?? "";
        if ((element.value ?? "").trim().length > 0) {
          anyValue = true;
        }
      }

      try {
        if (!anyValue) {
          localStorage.removeItem(storageKey);
          setHasDraft(false);
          setSavedAt(null);
          return;
        }
        localStorage.setItem(storageKey, JSON.stringify(payload));
        setHasDraft(true);
        setSavedAt(Date.now());
      } catch {
        /* ignore storage quota/availability failures */
      }
    };

    restoreDraft();
    form.addEventListener("input", persist);
    form.addEventListener("change", persist);
    return () => {
      form.removeEventListener("input", persist);
      form.removeEventListener("change", persist);
    };
  }, [fields, fieldSet, formId, storageKey, successSignal]);

  const clearDraft = () => {
    const form = document.getElementById(formId) as HTMLFormElement | null;
    if (form) {
      for (const element of Array.from(form.elements)) {
        if (
          !(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement)
        ) {
          continue;
        }
        if (!fieldSet.has(element.name) || element.type === "file") continue;
        element.value = "";
      }
    }
    try {
      localStorage.removeItem(storageKey);
    } catch {
      /* ignore */
    }
    setHasDraft(false);
    setSavedAt(null);
  };

  return (
    <div className={`flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 ${className}`.trim()}>
      <p>{formatTime(savedAt)}</p>
      {hasDraft ? (
        <button type="button" onClick={clearDraft} className="font-semibold text-slate-700 underline underline-offset-2">
          Clear draft
        </button>
      ) : null}
    </div>
  );
}
