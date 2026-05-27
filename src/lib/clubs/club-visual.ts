/** Accent palette for club cards and feed dots (deterministic by club name). */
export const CLUB_ACCENT_COLORS = ["#B5D4F4", "#AFA9EC", "#9FE1CB", "#FAC775", "#F0997B"] as const;

export type ClubAccentColor = (typeof CLUB_ACCENT_COLORS)[number];

export type ClubCoverIconKind = "award" | "camera" | "trending" | "users" | "star";

/**
 * Simple string hash for picking a stable accent color from the club name.
 */
export function hashClubName(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i += 1) {
    hash = (hash * 31 + name.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

export function getClubAccentColor(name: string): ClubAccentColor {
  return CLUB_ACCENT_COLORS[hashClubName(name) % CLUB_ACCENT_COLORS.length];
}

/** Two-letter initials for club avatar dots (not member privacy rules). */
export function getClubInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0]![0] ?? ""}${parts[1]![0] ?? ""}`.toUpperCase();
  }
  const compact = name.replace(/[^a-zA-Z0-9]/g, "");
  if (compact.length >= 2) return compact.slice(0, 2).toUpperCase();
  if (compact.length === 1) return `${compact}X`.toUpperCase();
  return "CL";
}

export function inferClubCoverIcon(name: string): ClubCoverIconKind {
  const n = name.toLowerCase();
  if (/\b(nhs|honor|honour|society)\b/.test(n) || n.includes("honor")) return "award";
  if (/\b(photo|photography|camera|film|media)\b/.test(n)) return "camera";
  if (/\b(business|fbla|deca|economics|finance|entrepreneur|marketing)\b/.test(n)) return "trending";
  if (/\b(star|award)\b/.test(n)) return "star";
  return "users";
}

export function clubAccentTextColor(hex: string): string {
  if (hex === "#FAC775" || hex === "#9FE1CB" || hex === "#B5D4F4") return "#1e293b";
  return "#ffffff";
}

export function buildClubColorMap(clubs: Array<{ id: string; name: string }>): Map<string, ClubAccentColor> {
  const map = new Map<string, ClubAccentColor>();
  for (const club of clubs) {
    map.set(club.id, getClubAccentColor(club.name));
  }
  return map;
}
