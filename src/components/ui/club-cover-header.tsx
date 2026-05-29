import type { ReactNode } from "react";
import {
  getClubAccentColor,
  getClubAccentIconColor,
  inferClubCoverIcon,
  type ClubCoverIconKind,
} from "@/lib/clubs/club-visual";
import type { ClubLayoutShell } from "@/lib/clubs/club-status";

type ClubCoverHeaderProps = {
  clubName: string;
  memberCount: number;
  userRole: ClubLayoutShell["userRole"];
  isArchived?: boolean;
  actions?: ReactNode;
};

function CoverIcon({ kind }: { kind: ClubCoverIconKind }) {
  const common = {
    width: 36,
    height: 36,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.75,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };

  switch (kind) {
    case "award":
      return (
        <svg {...common}>
          <path d="M8 21l4 -7l4 7" />
          <path d="M12 3a4 4 0 0 1 4 4v2a4 4 0 0 1 -8 0v-2a4 4 0 0 1 4 -4z" />
        </svg>
      );
    case "camera":
      return (
        <svg {...common}>
          <path d="M5 7h1a2 2 0 0 0 2 -2a1 1 0 0 1 1 -1h6a1 1 0 0 1 1 1a2 2 0 0 0 2 2h1a2 2 0 0 1 2 2v9a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-9a2 2 0 0 1 2 -2" />
          <path d="M12 13a3 3 0 1 0 0 -6a3 3 0 0 0 0 6z" />
        </svg>
      );
    case "trending":
      return (
        <svg {...common}>
          <path d="M3 17l6 -6l4 4l8 -8" />
          <path d="M14 7l7 0l0 7" />
        </svg>
      );
    case "star":
      return (
        <svg {...common}>
          <path d="M12 17.75l-6.172 3.245l1.179 -6.873l-5 -4.867l6.9 -1l3.093 -6.26l3.093 6.26l6.9 1l-5 4.867l1.179 6.873z" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <path d="M9 7m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0" />
          <path d="M3 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
          <path d="M16 3.13a4 4 0 0 1 0 7.75" />
          <path d="M21 21v-2a4 4 0 0 0 -3 -3.85" />
        </svg>
      );
  }
}

function formatMemberCount(count: number): string {
  return count === 1 ? "1 member" : `${count} members`;
}

function formatRoleLabel(role: ClubLayoutShell["userRole"]): string {
  return role === "officer" ? "Officer" : "Member";
}

export function ClubCoverHeader({ clubName, memberCount, userRole, isArchived = false, actions }: ClubCoverHeaderProps) {
  const accent = getClubAccentColor(clubName);
  const iconColor = getClubAccentIconColor(accent);
  const iconKind = inferClubCoverIcon(clubName);
  const metaLabel = `${formatMemberCount(memberCount)} · ${formatRoleLabel(userRole)}`;

  return (
    <header className="club-cover-header" style={{ backgroundColor: accent }}>
      <div className="club-cover-header__inner">
        <span className="club-cover-header__icon shrink-0" style={{ color: iconColor }}>
          <CoverIcon kind={iconKind} />
        </span>
        <div className="club-cover-header__text min-w-0 flex-1">
          <div className="club-cover-header__title-row">
            <h1 className="truncate">{clubName}</h1>
            {isArchived ? <span className="club-cover-header__archived">Archived</span> : null}
          </div>
          <p className="club-cover-header__meta">{metaLabel}</p>
        </div>
        {actions ? <div className="club-cover-header__actions shrink-0">{actions}</div> : null}
      </div>
    </header>
  );
}
