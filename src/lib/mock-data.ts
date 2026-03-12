export type MockClub = {
  id: string;
  slug: string;
  name: string;
  description: string;
  memberCount: number;
  role: "member" | "officer";
};

export type MockAnnouncement = {
  id: string;
  clubSlug: string;
  clubName: string;
  title: string;
  content: string;
  author: string;
  createdAt: string;
};

export type MockEvent = {
  id: string;
  clubSlug: string;
  clubName: string;
  title: string;
  description: string;
  location: string;
  eventDate: string;
  rsvpSummary: string;
};

export const mockClubs: MockClub[] = [
  {
    id: "club-1",
    slug: "muslim-student-association",
    name: "Muslim Student Association",
    description: "Weekly meetups, campus service, and community events.",
    memberCount: 46,
    role: "officer",
  },
  {
    id: "club-2",
    slug: "deca",
    name: "DECA",
    description: "Business competitions, workshops, and leadership prep.",
    memberCount: 38,
    role: "member",
  },
  {
    id: "club-3",
    slug: "robotics-club",
    name: "Robotics Club",
    description: "Hands-on engineering projects and regional robot challenges.",
    memberCount: 27,
    role: "member",
  },
];

export const mockAnnouncements: MockAnnouncement[] = [
  {
    id: "ann-1",
    clubSlug: "muslim-student-association",
    clubName: "Muslim Student Association",
    title: "Jummah Carpool Signup",
    content: "Please submit your ride preferences by Thursday evening.",
    author: "Amina Khan",
    createdAt: "Today at 9:15 AM",
  },
  {
    id: "ann-2",
    clubSlug: "deca",
    clubName: "DECA",
    title: "State Competition Practice",
    content: "Roleplay practice starts Friday at 4:00 PM in Room B-104.",
    author: "Marcus Reed",
    createdAt: "Yesterday at 6:10 PM",
  },
  {
    id: "ann-3",
    clubSlug: "robotics-club",
    clubName: "Robotics Club",
    title: "Build Session Schedule",
    content: "Saturday build session moved to the engineering lab.",
    author: "Noah Park",
    createdAt: "Monday at 3:40 PM",
  },
];

export const mockEvents: MockEvent[] = [
  {
    id: "event-2",
    clubSlug: "deca",
    clubName: "DECA",
    title: "Mock Pitch Night",
    description: "Practice your pitch and get judged feedback from officers.",
    location: "Business Lab 204",
    eventDate: "Mar 24, 2026 at 5:30 PM",
    rsvpSummary: "21 going",
  },
  {
    id: "event-3",
    clubSlug: "robotics-club",
    clubName: "Robotics Club",
    title: "Regional Scrimmage",
    description: "Friendly scrimmage ahead of regional qualifiers.",
    location: "Tech Gym",
    eventDate: "Mar 28, 2026 at 10:00 AM",
    rsvpSummary: "18 going",
  },
  {
    id: "event-1",
    clubSlug: "muslim-student-association",
    clubName: "Muslim Student Association",
    title: "Community Iftar",
    description: "A shared evening meal with students, staff, and families.",
    location: "Student Center Hall",
    eventDate: "Apr 2, 2026 at 7:10 PM",
    rsvpSummary: "32 going",
  },
];
