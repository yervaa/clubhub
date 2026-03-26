import "server-only";
import { unstable_noStore as noStore } from "next/cache";
import { createClient } from "@/lib/supabase/server";

export type UserClub = {
  id: string;
  name: string;
  description: string;
  joinCode: string;
  role: "member" | "officer";
};

export type ClubAnnouncement = {
  id: string;
  title: string;
  content: string;
  createdAt: string;
};

export type ClubEvent = {
  id: string;
  title: string;
  description: string;
  location: string;
  eventDate: string;
  eventDateRaw: Date;
  userRsvpStatus: "yes" | "no" | "maybe" | null;
  rsvpCounts: {
    yes: number;
    no: number;
    maybe: number;
  };
};

export type ClubMember = {
  userId: string;
  fullName: string | null;
  email: string | null;
  role: "member" | "officer";
};

export type ClubActivityItem = {
  id: string;
  kind: "member_joined" | "announcement_posted" | "event_created" | "rsvp_updated";
  message: string;
  createdAt: string;
};

export type ClubDetail = {
  id: string;
  name: string;
  description: string;
  joinCode: string;
  currentUserId: string;
  currentUserRole: "member" | "officer";
  members: ClubMember[];
  recentActivity: ClubActivityItem[];
  announcements: ClubAnnouncement[];
  events: ClubEvent[];
};

export type DashboardAnnouncement = {
  id: string;
  clubId: string;
  clubName: string;
  title: string;
  createdAt: string;
};

export type DashboardEvent = {
  id: string;
  clubId: string;
  clubName: string;
  title: string;
  location: string;
  eventDate: string;
};

export type DashboardData = {
  clubs: UserClub[];
  recentAnnouncements: DashboardAnnouncement[];
  upcomingEvents: DashboardEvent[];
};

type ClubMemberRow = {
  role: "member" | "officer";
  clubs:
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
      }
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
      }[]
    | null;
};

type ClubMemberViewRow = {
  user_id: string;
  full_name: string | null;
  email: string | null;
  role: "member" | "officer";
};

type ClubActivityRow = {
  id: string;
  kind: ClubActivityItem["kind"];
  message: string;
  created_at: string;
};

function normalizeClubRelation(
  relation:
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
      }
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
      }[]
    | null,
) {
  return Array.isArray(relation) ? relation[0] ?? null : relation;
}

export async function getCurrentUserClubs(): Promise<UserClub[]> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return [];
  }

  const { data, error } = await supabase
    .from("club_members")
    .select("role, clubs(id, name, description, join_code)")
    .eq("user_id", user.id)
    .order("joined_at", { ascending: false });

  if (error || !data) {
    return [];
  }

  const rows = data as unknown as ClubMemberRow[];

  return rows
    .map((row) => ({
      role: row.role,
      club: normalizeClubRelation(row.clubs),
    }))
    .filter((row) => row.club)
    .map((row) => ({
      id: row.club!.id,
      name: row.club!.name,
      description: row.club!.description,
      joinCode: row.club!.join_code,
      role: row.role,
    }));
}

export async function getDashboardData(): Promise<DashboardData> {
  noStore();

  const clubs = await getCurrentUserClubs();
  const clubIds = clubs.map((club) => club.id);

  if (clubIds.length === 0) {
    return {
      clubs: [],
      recentAnnouncements: [],
      upcomingEvents: [],
    };
  }

  const supabase = await createClient();
  const nowIso = new Date().toISOString();

  const { data: announcementsData } = await supabase
    .from("announcements")
    .select("id, title, created_at, club_id")
    .in("club_id", clubIds)
    .order("created_at", { ascending: false })
    .limit(8);

  const { data: eventsData } = await supabase
    .from("events")
    .select("id, title, location, event_date, club_id")
    .in("club_id", clubIds)
    .gte("event_date", nowIso)
    .order("event_date", { ascending: true })
    .limit(8);

  const clubNameById = new Map(clubs.map((club) => [club.id, club.name]));

  return {
    clubs,
    recentAnnouncements: (announcementsData ?? []).map((announcement) => ({
      id: announcement.id,
      clubId: announcement.club_id,
      clubName: clubNameById.get(announcement.club_id) ?? "Club",
      title: announcement.title,
      createdAt: new Date(announcement.created_at).toLocaleString(),
    })),
    upcomingEvents: (eventsData ?? []).map((event) => ({
      id: event.id,
      clubId: event.club_id,
      clubName: clubNameById.get(event.club_id) ?? "Club",
      title: event.title,
      location: event.location,
      eventDate: new Date(event.event_date).toLocaleString(),
    })),
  };
}

export async function getClubDetailForCurrentUser(clubId: string): Promise<ClubDetail | null> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return null;
  }

  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("role, clubs(id, name, description, join_code)")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership?.clubs) {
    return null;
  }

  const clubRelation = normalizeClubRelation(membership.clubs);
  if (!clubRelation) {
    return null;
  }

  const { data: membersData } = await supabase
    .rpc("get_club_members_for_view", { target_club_id: clubId });

  const { data: announcementsData } = await supabase
    .from("announcements")
    .select("id, title, content, created_at")
    .eq("club_id", clubId)
    .order("created_at", { ascending: false })
    .limit(10);

  const { data: activityData } = await supabase
    .rpc("get_club_recent_activity", { target_club_id: clubId });

  const { data: eventsData } = await supabase
    .from("events")
    .select("id, title, description, location, event_date")
    .eq("club_id", clubId)
    .order("event_date", { ascending: true })
    .limit(10);

  const eventIds = (eventsData ?? []).map((event) => event.id);

  const { data: rsvpData } =
    eventIds.length > 0
      ? await supabase
          .from("rsvps")
          .select("event_id, user_id, status")
          .in("event_id", eventIds)
      : { data: [] as { event_id: string; user_id: string; status: "yes" | "no" | "maybe" }[] };

  return {
    id: clubRelation.id,
    name: clubRelation.name,
    description: clubRelation.description,
    joinCode: clubRelation.join_code,
    currentUserId: user.id,
    currentUserRole: membership.role,
    members: ((membersData ?? []) as ClubMemberViewRow[]).map((member) => ({
      userId: member.user_id,
      fullName: member.full_name,
      email: member.email,
      role: member.role,
    })),
    recentActivity: ((activityData ?? []) as ClubActivityRow[]).map((item) => ({
      id: item.id,
      kind: item.kind,
      message: item.message,
      createdAt: new Date(item.created_at).toLocaleString(),
    })),
    announcements: (announcementsData ?? []).map((announcement) => ({
      id: announcement.id,
      title: announcement.title,
      content: announcement.content,
      createdAt: new Date(announcement.created_at).toLocaleString(),
    })),
    events: (eventsData ?? []).map((event) => ({
      id: event.id,
      title: event.title,
      description: event.description,
      location: event.location,
      eventDate: new Date(event.event_date).toLocaleString(),
      eventDateRaw: new Date(event.event_date),
      userRsvpStatus:
        (rsvpData ?? []).find((rsvp) => rsvp.event_id === event.id && rsvp.user_id === user.id)?.status ?? null,
      rsvpCounts: {
        yes: (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id && rsvp.status === "yes").length,
        no: (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id && rsvp.status === "no").length,
        maybe: (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id && rsvp.status === "maybe").length,
      },
    })),
  };
}
