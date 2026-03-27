"use client";

import { useState } from "react";

type AnnouncementGeneratorProps = {
  titleSelector: string;
  contentSelector: string;
};

function normalizePrompt(value: string) {
  return value.replace(/[<>]/g, "").replace(/\s+/g, " ").trim();
}

function toSentence(value: string) {
  if (!value) {
    return "";
  }

  const trimmed = value.replace(/[.!?]+$/g, "").trim();
  if (!trimmed) {
    return "";
  }

  return `${trimmed.charAt(0).toUpperCase()}${trimmed.slice(1)}.`;
}

function buildAnnouncement(prompt: string) {
  const cleanPrompt = normalizePrompt(prompt);
  const sentence = toSentence(cleanPrompt);
  const lowerPrompt = cleanPrompt.toLowerCase();

  const title = (() => {
    if (lowerPrompt.includes("meeting")) {
      return "Meeting Reminder";
    }
    if (lowerPrompt.includes("event")) {
      return "Event Reminder";
    }
    if (lowerPrompt.includes("practice")) {
      return "Practice Update";
    }
    if (lowerPrompt.includes("fundraiser")) {
      return "Fundraiser Update";
    }

    return "Club Update";
  })();

  const content = (() => {
    if (!sentence) {
      return "";
    }

    if (lowerPrompt.includes("meeting")) {
      return `Reminder: We have ${sentence.toLowerCase()} Please be on time.`;
    }

    if (lowerPrompt.includes("event")) {
      return `Heads up: ${sentence} We hope to see everyone there.`;
    }

    if (lowerPrompt.includes("practice")) {
      return `Quick update: ${sentence} Please plan ahead and be ready.`;
    }

    return `Reminder: ${sentence} Please check in with the club if you have any questions.`;
  })();

  return { title, content };
}

export function AnnouncementGenerator({
  titleSelector,
  contentSelector,
}: AnnouncementGeneratorProps) {
  const [prompt, setPrompt] = useState("");
  const [status, setStatus] = useState("");

  const handleGenerate = () => {
    const cleanPrompt = normalizePrompt(prompt);
    if (!cleanPrompt) {
      setStatus("Add a short prompt first.");
      return;
    }

    const titleInput = document.querySelector(titleSelector) as HTMLInputElement | null;
    const contentInput = document.querySelector(contentSelector) as HTMLTextAreaElement | null;

    if (!titleInput || !contentInput) {
      setStatus("Could not find the announcement form.");
      return;
    }

    const generated = buildAnnouncement(cleanPrompt);
    titleInput.value = generated.title;
    contentInput.value = generated.content;
    titleInput.dispatchEvent(new Event("input", { bubbles: true }));
    contentInput.dispatchEvent(new Event("input", { bubbles: true }));
    contentInput.focus();
    setStatus("Draft added to the form.");
  };

  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50/70 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-900">Quick draft</p>
          <p className="mt-1 text-sm text-slate-600">Describe what you want to say and get a draft filled in instantly.</p>
        </div>
        <span className="badge-soft">Template</span>
      </div>
      <div className="mt-4 flex flex-col gap-3 sm:flex-row">
        <input
          type="text"
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
          className="input-control flex-1"
          placeholder="meeting tomorrow after school"
        />
        <button type="button" onClick={handleGenerate} className="btn-secondary whitespace-nowrap">
          Generate announcement
        </button>
      </div>
      {status ? <p className="mt-3 text-xs font-medium text-slate-500">{status}</p> : null}
    </div>
  );
}
