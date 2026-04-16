"use client";

import { useMemo, useState } from "react";

type CopyInviteLinkButtonProps = {
  joinCode: string;
  className?: string;
  children?: React.ReactNode;
};

export function CopyInviteLinkButton({
  joinCode,
  className = "",
  children = "Copy Invite Link",
}: CopyInviteLinkButtonProps) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);
  const invitePath = useMemo(() => `/join?code=${encodeURIComponent(joinCode)}`, [joinCode]);

  const handleCopy = async () => {
    const inviteUrl = `${window.location.origin}${invitePath}`;
    setError(false);
    try {
      await navigator.clipboard.writeText(inviteUrl);
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
      {copied ? "Invite link copied" : error ? "Could not copy - try again" : children}
    </button>
  );
}
