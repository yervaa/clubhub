"use client";

import { useCallback, useState } from "react";

const MAX_OPTIONS = 10;

/**
 * Renders poll option inputs; each uses name="poll_option" so FormData collects all values.
 */
export function PollOptionFields() {
  const [count, setCount] = useState(2);

  const add = useCallback(() => {
    setCount((c) => Math.min(MAX_OPTIONS, c + 1));
  }, []);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-slate-600">Poll options (2–10)</p>
        {count < MAX_OPTIONS ? (
          <button
            type="button"
            onClick={add}
            className="text-xs font-semibold text-slate-700 underline decoration-slate-300 underline-offset-2 hover:text-slate-900"
          >
            Add option
          </button>
        ) : null}
      </div>
      {Array.from({ length: count }, (_, i) => (
        <input
          key={i}
          name="poll_option"
          type="text"
          className="input-control"
          placeholder={`Option ${i + 1}`}
          maxLength={200}
          aria-label={`Poll option ${i + 1}`}
        />
      ))}
    </div>
  );
}
