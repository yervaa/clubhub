"use client";

import { useState } from "react";

type CopyJoinCodeButtonProps = {
  joinCode: string;
  className?: string;
};

export function CopyJoinCodeButton({ joinCode, className = "" }: CopyJoinCodeButtonProps) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);

  const handleCopy = async () => {
    setError(false);
    try {
      await navigator.clipboard.writeText(joinCode);
      setCopied(true);
    } catch {
      setCopied(false);
      setError(true);
    }
    window.setTimeout(() => setCopied(false), 1800);
    window.setTimeout(() => setError(false), 2200);
  };

  return (
    <button type="button" onClick={handleCopy} className={className} disabled={copied} aria-live="polite">
      {copied ? "Join code copied" : error ? "Could not copy - try again" : "Copy join code"}
    </button>
  );
}
