export type NavMatchMode = "exact" | "prefix";

export function isPathActive(pathname: string, href: string, match: NavMatchMode = "prefix"): boolean {
  if (match === "exact") {
    return pathname === href;
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function getActiveClubId(pathname: string): string | null {
  const match = pathname.match(/^\/clubs\/([^/]+)/);
  return match ? match[1] : null;
}
