/**
 * User-facing copy for `remove_club_member` / `set_club_membership_alumni` RPC status codes.
 */

export function getMemberManagementErrorMessage(status: string): string {
  switch (status) {
    case "cannot_edit_self":
      return "You cannot change your own membership from this screen.";
    case "last_officer":
      return "This club must keep at least one officer.";
    case "last_president":
      return "This club must keep at least one President — assign another President before marking this member as alumni.";
    case "already_alumni":
      return "That member is already marked as alumni.";
    case "not_found":
      return "That member could not be found in this club.";
    case "not_allowed":
      return "Only officers can manage members.";
    default:
      return "Unable to update this member right now.";
  }
}
