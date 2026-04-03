type MemberIdentity = {
  fullName: string | null;
  email: string | null;
};

export function getMemberDisplayName(member: MemberIdentity) {
  const name = member.fullName?.trim();
  if (name) {
    return name;
  }

  if (member.email) {
    return member.email;
  }

  return "Member";
}

export function getMemberSecondaryText(member: MemberIdentity) {
  return member.email ?? "Club member";
}

export function getMemberInitials(member: MemberIdentity) {
  const name = member.fullName?.trim();

  if (name) {
    const parts = name.split(/\s+/).filter(Boolean).slice(0, 2);
    return parts.map((part) => part[0]?.toUpperCase() ?? "").join("") || "M";
  }

  if (member.email) {
    return member.email.charAt(0).toUpperCase();
  }

  return "M";
}

/** Roster / shared member list: do not use email as name or initials (privacy). */
export function getMemberRosterDisplayName(member: MemberIdentity): string {
  const name = member.fullName?.trim();
  if (name) return name;
  return "Member";
}

export function getMemberRosterInitials(member: MemberIdentity): string {
  const name = member.fullName?.trim();
  if (name) {
    const parts = name.split(/\s+/).filter(Boolean).slice(0, 2);
    return parts.map((part) => part[0]?.toUpperCase() ?? "").join("") || "M";
  }
  return "M";
}
