"use client";

import { useState } from "react";

type CopyJoinCodeButtonProps = {
  joinCode: string;
  className?: string;
};

export function CopyJoinCodeButton({ joinCode, className = "" }: CopyJoinCodeButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(joinCode);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <button type="button" onClick={handleCopy} className={className} disabled={copied} aria-live="polite">
      {copied ? "Join Code Copied" : "Copy Join Code"}
    </button>
  );
}
