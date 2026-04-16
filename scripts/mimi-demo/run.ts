/**
 * Mimi showcase seed for ClubHub.
 *
 * Creates a repeatable demo environment with:
 * - 1 primary user (Mimi) + realistic supporting roster
 * - 5 clubs (Spanish Honor Society, NHS, Science Honor Society, Model UN, FBLA)
 * - rich data across announcements, events, attendance, reflections, tasks, members metadata, dues, notifications
 *
 * Safety:
 * - Only touches designated demo join codes and designated demo emails in this file
 * - Refuses production unless ALLOW_DEMO_SEED=true
 * - Refuses non-loopback target unless DEMO_SEED_TARGET_OK=true
 */

import path from "path";
import { config } from "dotenv";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { DEMO_SEED_ENV_FLAG, DEMO_SEED_REMOTE_OK_FLAG } from "../demo-seed/constants";
import { seedSystemRolesForClub } from "../demo-seed/rbac";

config({ path: path.resolve(process.cwd(), ".env.local") });
config({ path: path.resolve(process.cwd(), ".env") });

type EventType = "Meeting" | "Workshop" | "Social" | "Competition" | "Fundraiser" | "Service" | "Other";
type TaskStatus = "todo" | "in_progress" | "blocked" | "completed";
type TaskPriority = "low" | "medium" | "high" | "urgent";

type Person = {
  slug: string;
  fullName: string;
  email: string;
};

type ClubPlan = {
  slug: string;
  name: string;
  joinCode: string;
  description: string;
  requireJoinApproval: boolean;
  president: string;
  officers: string[];
  members: string[];
  tags: string[];
  committees: string[];
  teams: string[];
  duesLabel: string;
  duesAmountCents: number;
  duesDueDateOffsetDays: number;
  announcements: Array<{
    title: string;
    content: string;
    daysAgo: number;
    by: string;
    pollQuestion?: string;
    pollOptions?: string[];
    scheduledDaysAgo?: number;
    addAttachment?: boolean;
  }>;
  events: Array<{
    title: string;
    description: string;
    location: string;
    eventType: EventType;
    dayOffset: number;
    addReflection?: boolean;
  }>;
  tasks: Array<{
    title: string;
    description: string;
    status: TaskStatus;
    priority: TaskPriority;
    dueDayOffset: number | null;
    creator: string;
    assignees: string[];
  }>;
};

const MIMI_EMAIL = (process.env.MIMI_DEMO_EMAIL ?? "mimi.demo@clubhub.app").trim().toLowerCase();
const MIMI_PASSWORD = (process.env.MIMI_DEMO_PASSWORD ?? "DemoClubHub!2026").trim();
const SUPPORTING_PASSWORD = (process.env.MIMI_DEMO_SUPPORT_PASSWORD ?? "ClubHubDemo!2026").trim();

const PEOPLE: Person[] = [
  { slug: "mimi", fullName: "Mimi Alvarez", email: MIMI_EMAIL },
  { slug: "sophia", fullName: "Sophia Ramirez", email: "sophia.demo@clubhub.app" },
  { slug: "ethan", fullName: "Ethan Kim", email: "ethan.demo@clubhub.app" },
  { slug: "ava", fullName: "Ava Patel", email: "ava.demo@clubhub.app" },
  { slug: "liam", fullName: "Liam Carter", email: "liam.demo@clubhub.app" },
  { slug: "isabella", fullName: "Isabella Nguyen", email: "isabella.demo@clubhub.app" },
  { slug: "noah", fullName: "Noah Thompson", email: "noah.demo@clubhub.app" },
  { slug: "maya", fullName: "Maya Gonzales", email: "maya.demo@clubhub.app" },
  { slug: "daniel", fullName: "Daniel Park", email: "daniel.demo@clubhub.app" },
  { slug: "nora", fullName: "Nora Hassan", email: "nora.demo@clubhub.app" },
  { slug: "elena", fullName: "Elena Rossi", email: "elena.demo@clubhub.app" },
  { slug: "julian", fullName: "Julian Rivera", email: "julian.demo@clubhub.app" },
  { slug: "amara", fullName: "Amara Brooks", email: "amara.demo@clubhub.app" },
  { slug: "owen", fullName: "Owen Lee", email: "owen.demo@clubhub.app" },
  { slug: "priya", fullName: "Priya Shah", email: "priya.demo@clubhub.app" },
  { slug: "gabriel", fullName: "Gabriel Flores", email: "gabriel.demo@clubhub.app" },
];

const CLUBS: ClubPlan[] = [
  {
    slug: "spanish-honor-society",
    name: "Spanish Honor Society",
    joinCode: "SPANHS01",
    description:
      "Celebrates Spanish language and culture through peer tutoring, conversation practice, and cultural programming. Meets Tuesdays after school in World Languages 204.",
    requireJoinApproval: false,
    president: "sophia",
    officers: ["maya"],
    members: ["mimi", "liam", "isabella", "daniel", "nora", "elena"],
    tags: ["Tutor", "Conversation Lead", "Event Crew"],
    committees: ["Cultural Events", "Tutoring", "Recruitment"],
    teams: ["Heritage Night", "Peer Tutors"],
    duesLabel: "Spring 2026 SHH Dues",
    duesAmountCents: 2500,
    duesDueDateOffsetDays: -12,
    announcements: [
      {
        title: "Hispanic Heritage Night volunteer shifts",
        content:
          "Please pick a setup or welcome-table shift before Thursday. We are also looking for two bilingual MC volunteers for opening remarks.",
        daysAgo: 2,
        by: "sophia",
        pollQuestion: "Which station should get extra volunteers?",
        pollOptions: ["Welcome table", "Food service", "Cultural exhibit"],
        addAttachment: true,
      },
      {
        title: "Peer tutoring hours posted",
        content:
          "Spanish tutoring starts this week during lunch. If you are available at least one day, add your name to the tutor board by Wednesday.",
        daysAgo: 6,
        by: "maya",
        scheduledDaysAgo: 5,
      },
      {
        title: "Conversation circle location update",
        content:
          "This Friday's conversation circle will be in the library seminar room, not 204. Bring your discussion prompts and name tags.",
        daysAgo: 10,
        by: "sophia",
      },
    ],
    events: [
      {
        title: "After-school conversation practice",
        description: "Small-group speaking practice focused on fluency and confidence.",
        location: "World Languages 204",
        eventType: "Meeting",
        dayOffset: 5,
      },
      {
        title: "Community Spanish tutoring session",
        description: "Peer tutors support Spanish I and II students with quiz prep.",
        location: "Library tutoring center",
        eventType: "Service",
        dayOffset: 14,
      },
      {
        title: "Hispanic Heritage Night",
        description: "Family event with performances, food booths, and student exhibits.",
        location: "School courtyard",
        eventType: "Social",
        dayOffset: -7,
        addReflection: true,
      },
      {
        title: "Exam prep workshop",
        description: "Grammar review and speaking station rotations for finals week.",
        location: "World Languages 201",
        eventType: "Workshop",
        dayOffset: -21,
        addReflection: true,
      },
    ],
    tasks: [
      {
        title: "Finalize Heritage Night run-of-show",
        description: "Confirm emcee script timing and performance order.",
        status: "in_progress",
        priority: "high",
        dueDayOffset: 2,
        creator: "sophia",
        assignees: ["mimi", "maya"],
      },
      {
        title: "Print conversation circle prompt cards",
        description: "Need 40 cards, double-sided, by Friday lunch.",
        status: "todo",
        priority: "medium",
        dueDayOffset: 5,
        creator: "maya",
        assignees: ["liam"],
      },
      {
        title: "Collect snack reimbursement forms",
        description: "Missing receipts from last workshop.",
        status: "blocked",
        priority: "urgent",
        dueDayOffset: -1,
        creator: "sophia",
        assignees: ["daniel"],
      },
      {
        title: "Post tutoring schedule graphic",
        description: "Shared on classroom slides and Instagram story.",
        status: "completed",
        priority: "low",
        dueDayOffset: -6,
        creator: "maya",
        assignees: ["elena"],
      },
    ],
  },
  {
    slug: "national-honor-society",
    name: "National Honor Society",
    joinCode: "NATLHS01",
    description:
      "National Honor Society chapter focused on scholarship, leadership, and service. Members coordinate tutoring, service projects, and officer planning each week.",
    requireJoinApproval: true,
    president: "mimi",
    officers: ["ethan", "ava"],
    members: ["isabella", "noah", "amara", "owen", "priya", "gabriel"],
    tags: ["Service Core", "Peer Tutor", "Event Lead"],
    committees: ["Service Projects", "Tutoring", "Membership Review"],
    teams: ["Officer Cabinet", "Project Leads"],
    duesLabel: "NHS 2025-2026 Chapter Dues",
    duesAmountCents: 3000,
    duesDueDateOffsetDays: -20,
    announcements: [
      {
        title: "Monthly service-hour check-in",
        content:
          "Reminder: submit your verified service hours before Friday at 5 PM so we can finalize chapter totals and advisor reporting.",
        daysAgo: 1,
        by: "mimi",
        pollQuestion: "Which service project should we prioritize next month?",
        pollOptions: ["Food pantry sorting", "Elementary tutoring", "Campus cleanup"],
      },
      {
        title: "Officer coordination agenda posted",
        content:
          "Cabinet agenda is posted in the shared folder. Add your updates on tutoring placements and service partnerships by Wednesday.",
        daysAgo: 4,
        by: "ethan",
        addAttachment: true,
      },
      {
        title: "New member induction timeline",
        content:
          "Induction rehearsal is next Tuesday. Officers should arrive 20 minutes early for setup and check-in assignments.",
        daysAgo: 9,
        by: "mimi",
        scheduledDaysAgo: 8,
      },
      {
        title: "Tutoring block volunteers still needed",
        content:
          "We still need two Algebra tutors for Thursday. Please sign up if your schedule allows.",
        daysAgo: 14,
        by: "ava",
      },
    ],
    events: [
      {
        title: "Officer strategy meeting",
        description: "Review service-hour targets, tutoring coverage, and upcoming induction tasks.",
        location: "College & Career Center",
        eventType: "Meeting",
        dayOffset: 3,
      },
      {
        title: "Community food pantry service day",
        description: "Chapter volunteer shift with check-in and hour verification.",
        location: "Downtown Community Pantry",
        eventType: "Service",
        dayOffset: 12,
      },
      {
        title: "Peer tutoring support block",
        description: "NHS members tutor underclassmen in math, science, and writing.",
        location: "Library tutoring center",
        eventType: "Service",
        dayOffset: -5,
        addReflection: true,
      },
      {
        title: "Induction planning workshop",
        description: "Finalize script, student speakers, and ceremony logistics.",
        location: "Auditorium green room",
        eventType: "Workshop",
        dayOffset: -18,
        addReflection: true,
      },
    ],
    tasks: [
      {
        title: "Finalize induction ceremony speaker list",
        description: "Confirm student speakers and faculty welcome remarks.",
        status: "in_progress",
        priority: "high",
        dueDayOffset: 2,
        creator: "mimi",
        assignees: ["ethan"],
      },
      {
        title: "Verify submitted service-hour logs",
        description: "Review entries and flag any missing supervisor confirmation.",
        status: "todo",
        priority: "high",
        dueDayOffset: 1,
        creator: "mimi",
        assignees: ["ava", "priya"],
      },
      {
        title: "Reserve meeting room for tutoring kickoff",
        description: "Need projector and 4 tutoring tables.",
        status: "todo",
        priority: "medium",
        dueDayOffset: 6,
        creator: "ethan",
        assignees: ["isabella"],
      },
      {
        title: "Upload ceremony photo recap",
        description: "Caption + officer recognition tags.",
        status: "completed",
        priority: "low",
        dueDayOffset: -8,
        creator: "ava",
        assignees: ["gabriel"],
      },
      {
        title: "Submit advisor reimbursement sheet",
        description: "Past-due from prior service transport receipts.",
        status: "blocked",
        priority: "urgent",
        dueDayOffset: -2,
        creator: "mimi",
        assignees: ["owen"],
      },
    ],
  },
  {
    slug: "science-honor-society",
    name: "Science Honor Society",
    joinCode: "SCIHONS1",
    description:
      "Science Honor Society supports STEM outreach, peer lab help sessions, and science fair mentoring. Weekly meetings in the STEM lab.",
    requireJoinApproval: false,
    president: "priya",
    officers: ["gabriel"],
    members: ["mimi", "ethan", "liam", "noah", "elena", "julian"],
    tags: ["Lab Mentor", "Outreach", "Science Fair Coach"],
    committees: ["Outreach", "Lab Support", "Science Fair"],
    teams: ["STEM Night", "Mentor Team"],
    duesLabel: "SHS Activity Fee Spring 2026",
    duesAmountCents: 2000,
    duesDueDateOffsetDays: 16,
    announcements: [
      {
        title: "Science fair mentor pairings posted",
        content:
          "Mentor pairings are in the shared sheet. Reach out to your mentee today and set one check-in before next week.",
        daysAgo: 2,
        by: "priya",
      },
      {
        title: "STEM outreach volunteer signup",
        content:
          "We are visiting Jefferson Middle School next Thursday. Volunteers should arrive by 3:10 for setup.",
        daysAgo: 6,
        by: "gabriel",
        pollQuestion: "Which station should we add this month?",
        pollOptions: ["Chem demo", "Robot challenge", "Astronomy lab"],
      },
      {
        title: "Lab safety refresher slide deck",
        content:
          "Please review before Thursday's hands-on workshop. We will start with a quick safety check.",
        daysAgo: 11,
        by: "priya",
        addAttachment: true,
      },
    ],
    events: [
      {
        title: "Weekly lab help session",
        description: "Drop-in support for chemistry and biology lab reports.",
        location: "STEM Lab 3",
        eventType: "Meeting",
        dayOffset: 4,
      },
      {
        title: "Middle school STEM outreach",
        description: "Hands-on demonstrations and Q&A with middle school students.",
        location: "Jefferson Middle School",
        eventType: "Service",
        dayOffset: 13,
      },
      {
        title: "Science fair rubric workshop",
        description: "Review judging criteria and poster feedback examples.",
        location: "STEM Lab 1",
        eventType: "Workshop",
        dayOffset: -6,
        addReflection: true,
      },
      {
        title: "Peer lab practical review",
        description: "Stations for data analysis and experiment design feedback.",
        location: "Science wing commons",
        eventType: "Workshop",
        dayOffset: -17,
        addReflection: true,
      },
    ],
    tasks: [
      {
        title: "Prepare materials for outreach station kits",
        description: "Inventory all kits and restock missing supplies.",
        status: "in_progress",
        priority: "high",
        dueDayOffset: 3,
        creator: "priya",
        assignees: ["mimi", "gabriel"],
      },
      {
        title: "Create volunteer timeline for STEM night",
        description: "Include setup, hosting, and cleanup blocks.",
        status: "todo",
        priority: "medium",
        dueDayOffset: 8,
        creator: "gabriel",
        assignees: ["julian"],
      },
      {
        title: "Submit guest speaker request form",
        description: "Still waiting on advisor signature.",
        status: "blocked",
        priority: "urgent",
        dueDayOffset: -3,
        creator: "priya",
        assignees: ["noah"],
      },
      {
        title: "Upload lab-review handout edits",
        description: "Version 2 includes revised chemistry examples.",
        status: "completed",
        priority: "low",
        dueDayOffset: -5,
        creator: "gabriel",
        assignees: ["elena"],
      },
    ],
  },
  {
    slug: "model-un-club",
    name: "Model UN Club",
    joinCode: "MODELUN1",
    description:
      "Model UN trains delegates in research, committee procedure, and position paper writing. Conference prep and simulations run throughout the semester.",
    requireJoinApproval: true,
    president: "julian",
    officers: ["mimi", "amara"],
    members: ["ethan", "ava", "owen", "liam", "nora", "daniel"],
    tags: ["Committee Chair", "Resolution Lead", "Research Mentor"],
    committees: ["Conference Prep", "Research", "Logistics"],
    teams: ["Security Council", "GA Delegation"],
    duesLabel: "Model UN Conference Fund 2026",
    duesAmountCents: 4500,
    duesDueDateOffsetDays: -9,
    announcements: [
      {
        title: "Position paper checkpoint this Friday",
        content:
          "Delegates should upload first drafts before Friday 8 PM. Officers will provide tracked comments over the weekend.",
        daysAgo: 1,
        by: "julian",
      },
      {
        title: "Conference committee assignments released",
        content:
          "Assignments are posted in the shared folder. Review your country background guide and start bloc outreach notes.",
        daysAgo: 5,
        by: "mimi",
        addAttachment: true,
      },
      {
        title: "Practice simulation agenda",
        content:
          "Thursday simulation will focus on moderated caucus strategy and resolution amendment flow.",
        daysAgo: 9,
        by: "amara",
        pollQuestion: "What should we spend extra time on this week?",
        pollOptions: ["Opening speeches", "Clause writing", "Caucus strategy"],
      },
    ],
    events: [
      {
        title: "Delegate prep meeting",
        description: "Country briefings, bloc mapping, and speaking-order drills.",
        location: "Social Studies 110",
        eventType: "Meeting",
        dayOffset: 2,
      },
      {
        title: "Position paper writing workshop",
        description: "Research citation standards and argument structure clinic.",
        location: "Library collaboration room",
        eventType: "Workshop",
        dayOffset: 9,
      },
      {
        title: "Full committee simulation",
        description: "Timed committee session with caucus and resolution debate.",
        location: "Auditorium breakout rooms",
        eventType: "Competition",
        dayOffset: -4,
        addReflection: true,
      },
      {
        title: "Resolution editing sprint",
        description: "Officer review of draft clauses before mock conference.",
        location: "Social Studies 108",
        eventType: "Workshop",
        dayOffset: -15,
        addReflection: true,
      },
    ],
    tasks: [
      {
        title: "Review delegate position paper drafts",
        description: "Provide comments on clarity, citations, and policy asks.",
        status: "in_progress",
        priority: "high",
        dueDayOffset: 1,
        creator: "julian",
        assignees: ["mimi", "amara"],
      },
      {
        title: "Finalize conference travel packet",
        description: "Include itinerary, permissions, and emergency contact sheet.",
        status: "todo",
        priority: "high",
        dueDayOffset: 6,
        creator: "mimi",
        assignees: ["owen"],
      },
      {
        title: "Reserve rooms for simulation day",
        description: "Need 3 breakout rooms plus one plenary room.",
        status: "todo",
        priority: "medium",
        dueDayOffset: 4,
        creator: "amara",
        assignees: ["daniel"],
      },
      {
        title: "Submit committee placard print order",
        description: "Past due from last simulation prep.",
        status: "blocked",
        priority: "urgent",
        dueDayOffset: -2,
        creator: "julian",
        assignees: ["nora"],
      },
      {
        title: "Publish simulation recap",
        description: "Highlight best delegate moments and next prep targets.",
        status: "completed",
        priority: "low",
        dueDayOffset: -5,
        creator: "mimi",
        assignees: ["ethan"],
      },
    ],
  },
  {
    slug: "fbla",
    name: "FBLA",
    joinCode: "FBLA2026",
    description:
      "Future Business Leaders of America chapter focused on competitive events, business workshops, and leadership development for regional and state conferences.",
    requireJoinApproval: false,
    president: "owen",
    officers: ["amara"],
    members: ["mimi", "sophia", "ethan", "ava", "isabella", "gabriel"],
    tags: ["Competition Prep", "Workshop Host", "Fundraising"],
    committees: ["Competition Team", "Workshops", "Sponsorship"],
    teams: ["Presentation Team", "Case Study Team"],
    duesLabel: "FBLA Competition Dues 2026",
    duesAmountCents: 3500,
    duesDueDateOffsetDays: 4,
    announcements: [
      {
        title: "Regional competition registration window",
        content:
          "Registration closes this Friday. Submit your event preference and waiver so we can finalize the roster.",
        daysAgo: 2,
        by: "owen",
      },
      {
        title: "Business pitch workshop deck",
        content:
          "Deck is uploaded with judging rubric notes. Review before Thursday's prep session.",
        daysAgo: 6,
        by: "amara",
        addAttachment: true,
      },
      {
        title: "Mock presentation order",
        content:
          "Presentation order is posted in the drive. First round starts at 3:20 and each team gets 7 minutes plus Q&A.",
        daysAgo: 11,
        by: "owen",
        pollQuestion: "Which workshop should we run next?",
        pollOptions: ["Financial literacy", "Leadership interviews", "Business ethics"],
      },
    ],
    events: [
      {
        title: "Competition event strategy meeting",
        description: "Assign events and prep plans for regional qualifiers.",
        location: "Business Lab 118",
        eventType: "Meeting",
        dayOffset: 3,
      },
      {
        title: "Guest workshop: startup finance basics",
        description: "Local entrepreneur Q&A and practical budgeting tips.",
        location: "College & Career Center",
        eventType: "Workshop",
        dayOffset: 10,
      },
      {
        title: "Mock presentation round",
        description: "Timed presentations with judge-style feedback.",
        location: "Business Lab 116",
        eventType: "Competition",
        dayOffset: -5,
        addReflection: true,
      },
      {
        title: "Leadership skills clinic",
        description: "Communication, delegation, and conflict-resolution practice.",
        location: "Library seminar room",
        eventType: "Workshop",
        dayOffset: -16,
        addReflection: true,
      },
    ],
    tasks: [
      {
        title: "Finalize regional event roster",
        description: "Confirm student event assignments and alternates.",
        status: "in_progress",
        priority: "high",
        dueDayOffset: 2,
        creator: "owen",
        assignees: ["mimi", "amara"],
      },
      {
        title: "Book transportation request for competition day",
        description: "Need bus estimate approved by activities office.",
        status: "todo",
        priority: "high",
        dueDayOffset: 5,
        creator: "amara",
        assignees: ["gabriel"],
      },
      {
        title: "Collect payment confirmations from members",
        description: "Still missing two payment screenshots.",
        status: "blocked",
        priority: "urgent",
        dueDayOffset: -1,
        creator: "owen",
        assignees: ["isabella"],
      },
      {
        title: "Post workshop recap to club feed",
        description: "Highlight top takeaways and upcoming deadlines.",
        status: "completed",
        priority: "low",
        dueDayOffset: -7,
        creator: "amara",
        assignees: ["ava"],
      },
    ],
  },
];

function nowIsoWithOffsetDays(days: number, hour = 16): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  d.setUTCHours(hour, 0, 0, 0);
  return d.toISOString();
}

function dateOnlyWithOffsetDays(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function assertSafeToRun(): void {
  const explicit = process.env[DEMO_SEED_ENV_FLAG] === "true";
  const vercelProd = process.env.VERCEL_ENV === "production";
  const nodeProd = process.env.NODE_ENV === "production";
  if (!explicit && (vercelProd || nodeProd)) {
    throw new Error(
      `Refused: this seed is blocked in production. Set ${DEMO_SEED_ENV_FLAG}=true only for intentional demo seeding.`,
    );
  }
}

function assertRemoteTargetOptIn(): void {
  const raw = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  if (!raw) return;
  let host = "";
  try {
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    return;
  }
  const isLoopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  if (isLoopback) return;
  if (process.env[DEMO_SEED_REMOTE_OK_FLAG] !== "true") {
    throw new Error(
      `Refused: non-loopback Supabase target (${host}). Set ${DEMO_SEED_REMOTE_OK_FLAG}=true for explicit confirmation.`,
    );
  }
}

function personIdBySlug(idsBySlug: Map<string, string>, slug: string): string {
  const id = idsBySlug.get(slug);
  if (!id) throw new Error(`Missing user id for slug ${slug}`);
  return id;
}

function isMissingRelationError(err: unknown): boolean {
  const code = String((err as { code?: unknown })?.code ?? "");
  const text = String((err as { message?: unknown })?.message ?? err ?? "").toLowerCase();
  return (
    code === "PGRST205" ||
    text.includes("does not exist") ||
    text.includes("relation") ||
    text.includes("column") ||
    text.includes("schema cache") ||
    text.includes("could not find the table")
  );
}

async function listAllAuthUsers(admin: SupabaseClient): Promise<Array<{ id: string; email: string }>> {
  const users: Array<{ id: string; email: string }> = [];
  const perPage = 200;
  for (let page = 1; page <= 100; page += 1) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const batch = data.users.map((u) => ({ id: u.id, email: (u.email ?? "").toLowerCase() }));
    users.push(...batch);
    if (batch.length < perPage) break;
  }
  return users;
}

async function deleteDemoClubs(admin: SupabaseClient): Promise<void> {
  const joinCodes = CLUBS.map((c) => c.joinCode);
  const { error } = await admin.rpc("delete_demo_clubs_by_join_codes", { p_join_codes: joinCodes });
  if (error) {
    if (String(error.message ?? "").includes("delete_demo_clubs_by_join_codes") || error.code === "PGRST202") {
      throw new Error(
        "Missing RPC delete_demo_clubs_by_join_codes. Apply supabase/022_demo_seed_club_delete.sql then rerun.",
      );
    }
    throw error;
  }
}

async function deleteDesignatedUsers(admin: SupabaseClient): Promise<void> {
  const targetEmails = new Set(PEOPLE.map((p) => p.email.toLowerCase()));
  const users = await listAllAuthUsers(admin);
  for (const user of users) {
    if (!targetEmails.has(user.email)) continue;
    const { error } = await admin.auth.admin.deleteUser(user.id);
    if (error) throw error;
  }
}

async function createUsersAndProfiles(admin: SupabaseClient): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  const usersByEmail = new Map((await listAllAuthUsers(admin)).map((u) => [u.email, u.id]));

  for (const person of PEOPLE) {
    const email = person.email.toLowerCase();
    const password = person.slug === "mimi" ? MIMI_PASSWORD : SUPPORTING_PASSWORD;
    const existingId = usersByEmail.get(email);
    let userId = existingId ?? "";

    if (existingId) {
      const { error } = await admin.auth.admin.updateUserById(existingId, {
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: person.fullName },
      });
      if (error) throw error;
    } else {
      const { data, error } = await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: person.fullName },
      });
      if (error) throw error;
      if (!data.user?.id) throw new Error(`Failed to create auth user for ${email}`);
      userId = data.user.id;
    }

    const finalId = userId || existingId;
    if (!finalId) throw new Error(`Missing user id for ${email}`);

    const { error: profileError } = await admin.from("profiles").upsert(
      { id: finalId, full_name: person.fullName, email },
      { onConflict: "id" },
    );
    if (profileError) throw profileError;

    map.set(person.slug, finalId);
  }

  return map;
}

async function assignRolesForClub(
  admin: SupabaseClient,
  clubId: string,
  plan: ClubPlan,
  idsBySlug: Map<string, string>,
): Promise<void> {
  const allSlugs = new Set([plan.president, ...plan.officers, ...plan.members]);
  const officerSlugs = new Set([plan.president, ...plan.officers]);

  for (const slug of allSlugs) {
    const { error } = await admin.from("club_members").upsert(
      {
        club_id: clubId,
        user_id: personIdBySlug(idsBySlug, slug),
        role: officerSlugs.has(slug) ? "officer" : "member",
        membership_status: "active",
      },
      { onConflict: "club_id,user_id" },
    );
    if (error) throw error;
  }

  const { data: roleRows, error: roleError } = await admin
    .from("club_roles")
    .select("id, name")
    .eq("club_id", clubId)
    .in("name", ["President", "Officer", "Member"]);
  if (roleError) throw roleError;

  const roleIdByName = new Map((roleRows ?? []).map((r) => [r.name as string, r.id as string]));
  const presidentRoleId = roleIdByName.get("President");
  const officerRoleId = roleIdByName.get("Officer");
  const memberRoleId = roleIdByName.get("Member");
  if (!presidentRoleId || !officerRoleId || !memberRoleId) {
    throw new Error(`Missing system role IDs for club ${plan.name}`);
  }

  const roleRowsToInsert: Array<{ user_id: string; club_id: string; role_id: string }> = [];
  for (const slug of allSlugs) {
    const userId = personIdBySlug(idsBySlug, slug);
    if (slug === plan.president) {
      roleRowsToInsert.push({ user_id: userId, club_id: clubId, role_id: presidentRoleId });
      roleRowsToInsert.push({ user_id: userId, club_id: clubId, role_id: officerRoleId });
    } else if (officerSlugs.has(slug)) {
      roleRowsToInsert.push({ user_id: userId, club_id: clubId, role_id: officerRoleId });
      roleRowsToInsert.push({ user_id: userId, club_id: clubId, role_id: memberRoleId });
    } else {
      roleRowsToInsert.push({ user_id: userId, club_id: clubId, role_id: memberRoleId });
    }
  }
  const { error: memberRolesError } = await admin.from("member_roles").upsert(roleRowsToInsert, {
    onConflict: "user_id,club_id,role_id",
  });
  if (memberRolesError) throw memberRolesError;
}

async function seedAnnouncements(
  admin: SupabaseClient,
  clubId: string,
  plan: ClubPlan,
  idsBySlug: Map<string, string>,
  memberIds: string[],
): Promise<void> {
  const { data: insertedRows, error } = await admin
    .from("announcements")
    .insert(
      plan.announcements.map((a) => ({
        club_id: clubId,
        title: a.title,
        content: a.content,
        created_by: personIdBySlug(idsBySlug, a.by),
        created_at: nowIsoWithOffsetDays(-a.daysAgo, 11),
        poll_question: a.pollQuestion ?? null,
        poll_options: a.pollOptions ?? null,
        scheduled_for: a.scheduledDaysAgo ? nowIsoWithOffsetDays(-a.scheduledDaysAgo, 9) : null,
        is_published: true,
      })),
    )
    .select("id, title, poll_question");
  if (error) throw error;

  const rows = (insertedRows ?? []) as Array<{ id: string; title: string; poll_question: string | null }>;
  if (!rows.length) return;

  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    const template = plan.announcements[i];
    if (!template) continue;

    if (template.addAttachment) {
      try {
        const storagePath = `demo/mimi/${plan.slug}/announcement-${i + 1}.txt`;
        const uploadText = [
          `${plan.name} resource: ${row.title}`,
          "",
          "Demo attachment seeded by scripts/mimi-demo/run.ts.",
          "Used to make the announcements UI look populated for showcase use.",
        ].join("\n");

        const { error: uploadError } = await admin.storage
          .from("announcement-attachments")
          .upload(storagePath, Buffer.from(uploadText, "utf8"), {
            upsert: true,
            contentType: "text/plain",
          });
        if (!uploadError) {
          await admin.from("announcement_attachments").insert({
            announcement_id: row.id,
            file_url: storagePath,
            file_name: `${plan.slug}-resource-${i + 1}.txt`,
            file_type: "text/plain",
          });
        }
      } catch (attachmentError) {
        if (!isMissingRelationError(attachmentError)) throw attachmentError;
      }
    }

    if (row.poll_question) {
      try {
        const pollVotes = memberIds.slice(0, Math.min(memberIds.length, 8)).map((memberId, idx) => ({
          announcement_id: row.id,
          user_id: memberId,
          option_index: idx % Math.max(1, template.pollOptions?.length ?? 1),
        }));
        const { error: pollErr } = await admin.from("poll_votes").insert(pollVotes);
        if (pollErr && pollErr.code !== "23505") throw pollErr;
      } catch (pollError) {
        if (!isMissingRelationError(pollError)) throw pollError;
      }
    }

    try {
      const readRows = memberIds.slice(0, Math.min(memberIds.length, 10)).map((memberId, idx) => ({
        announcement_id: row.id,
        user_id: memberId,
        read_at: nowIsoWithOffsetDays(-(template.daysAgo - 1), 17 - (idx % 4)),
      }));
      const { error: readErr } = await admin.from("announcement_reads").upsert(readRows, {
        onConflict: "announcement_id,user_id",
      });
      if (readErr) throw readErr;
    } catch (readsError) {
      if (!isMissingRelationError(readsError)) throw readsError;
    }
  }
}

async function seedEventsTasksAndNotifications(
  admin: SupabaseClient,
  clubId: string,
  plan: ClubPlan,
  idsBySlug: Map<string, string>,
  memberIds: string[],
): Promise<void> {
  const presidentId = personIdBySlug(idsBySlug, plan.president);
  const { data: eventRows, error: eventError } = await admin
    .from("events")
    .insert(
      plan.events.map((event) => ({
        club_id: clubId,
        title: event.title,
        description: event.description,
        location: event.location,
        event_type: event.eventType,
        event_date: nowIsoWithOffsetDays(event.dayOffset, 16),
        created_by: presidentId,
      })),
    )
    .select("id, title");
  if (eventError) throw eventError;

  const eventIds = (eventRows ?? []).map((r) => r.id as string);
  if (eventIds.length) {
    const statuses = ["yes", "maybe", "yes", "no"] as const;
    const rsvpRows: Array<{ event_id: string; user_id: string; status: "yes" | "no" | "maybe" }> = [];
    for (const eventId of eventIds) {
      for (let idx = 0; idx < memberIds.length; idx += 1) {
        rsvpRows.push({
          event_id: eventId,
          user_id: memberIds[idx],
          status: statuses[idx % statuses.length],
        });
      }
    }
    const { error: rsvpError } = await admin.from("rsvps").upsert(rsvpRows, {
      onConflict: "event_id,user_id",
    });
    if (rsvpError && rsvpError.code !== "23505") throw rsvpError;

    const attendanceRows: Array<{ event_id: string; user_id: string; marked_by: string; marked_at: string }> = [];
    for (let idx = 0; idx < plan.events.length; idx += 1) {
      const eventTemplate = plan.events[idx];
      const eventId = eventIds[idx];
      if (!eventId || !eventTemplate || eventTemplate.dayOffset >= 0) continue;
      for (let memberIdx = 0; memberIdx < memberIds.length; memberIdx += 1) {
        if (memberIdx % 5 === 0) continue;
        attendanceRows.push({
          event_id: eventId,
          user_id: memberIds[memberIdx],
          marked_by: presidentId,
          marked_at: nowIsoWithOffsetDays(eventTemplate.dayOffset + 1, 18),
        });
      }
    }
    if (attendanceRows.length) {
      const { error: attendanceError } = await admin.from("event_attendance").upsert(attendanceRows, {
        onConflict: "event_id,user_id",
      });
      if (attendanceError && attendanceError.code !== "23505") throw attendanceError;
    }

    const reflectionRows = plan.events
      .map((event, idx) => ({ event, eventId: eventIds[idx] }))
      .filter((x) => x.eventId && x.event.dayOffset < 0 && x.event.addReflection)
      .map((x) => ({
        event_id: x.eventId,
        what_worked: "Strong turnout and clear role delegation improved execution.",
        what_didnt: "Announcements should go out 24 hours earlier for better prep.",
        notes: "Follow-up tasks assigned to officers for next cycle.",
        created_by: presidentId,
        updated_by: presidentId,
      }));
    if (reflectionRows.length) {
      const { error: reflectionError } = await admin.from("event_reflections").upsert(reflectionRows, {
        onConflict: "event_id",
      });
      if (reflectionError && reflectionError.code !== "23505") throw reflectionError;
    }
  }

  for (const task of plan.tasks) {
    const creatorId = personIdBySlug(idsBySlug, task.creator);
    const body: Record<string, unknown> = {
      club_id: clubId,
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      created_by: creatorId,
    };
    if (task.dueDayOffset !== null) {
      body.due_at = nowIsoWithOffsetDays(task.dueDayOffset, 17);
    }
    if (task.status === "completed") {
      body.completed_at = nowIsoWithOffsetDays(-2, 15);
    }

    const { data: insertedTask, error: taskError } = await admin.from("club_tasks").insert(body).select("id").single();
    if (taskError) throw taskError;
    const taskId = insertedTask.id as string;

    const assigneeRows = task.assignees.map((slug) => ({
      task_id: taskId,
      user_id: personIdBySlug(idsBySlug, slug),
    }));
    const { error: assigneeError } = await admin.from("club_task_assignees").upsert(assigneeRows, {
      onConflict: "task_id,user_id",
    });
    if (assigneeError && assigneeError.code !== "23505") throw assigneeError;
  }

  const mimiId = personIdBySlug(idsBySlug, "mimi");
  const notifications = [
    {
      user_id: mimiId,
      club_id: clubId,
      type: "announcement_created",
      title: `New update in ${plan.name}`,
      body: `${plan.announcements[0]?.title ?? "New announcement"} was posted.`,
      href: `/clubs/${clubId}/announcements`,
      is_read: false,
      metadata: {},
    },
    {
      user_id: mimiId,
      club_id: clubId,
      type: "event_reminder",
      title: `Upcoming event in ${plan.name}`,
      body: `${plan.events.find((e) => e.dayOffset > 0)?.title ?? "Upcoming event"} is coming up soon.`,
      href: `/clubs/${clubId}/events`,
      is_read: false,
      metadata: { clubName: plan.name },
    },
    {
      user_id: mimiId,
      club_id: clubId,
      type: "task_assigned",
      title: `Task assignment in ${plan.name}`,
      body: `${plan.tasks.find((t) => t.assignees.includes("mimi"))?.title ?? "A task"} is assigned to you.`,
      href: `/clubs/${clubId}/tasks`,
      is_read: false,
      metadata: {},
    },
  ];

  const { error: notificationError } = await admin.from("notifications").insert(notifications);
  if (notificationError) throw notificationError;
}

async function seedMemberMetadata(
  admin: SupabaseClient,
  clubId: string,
  plan: ClubPlan,
  idsBySlug: Map<string, string>,
): Promise<void> {
  const memberSlugs = [plan.president, ...plan.officers, ...plan.members];
  const uniqueSlugs = Array.from(new Set(memberSlugs));
  const memberIds = uniqueSlugs.map((slug) => personIdBySlug(idsBySlug, slug));
  const actorId = personIdBySlug(idsBySlug, plan.president);

  try {
    const { data: tagRows, error: tagError } = await admin
      .from("club_member_tags")
      .insert(plan.tags.map((name) => ({ club_id: clubId, name })))
      .select("id");
    if (tagError) throw tagError;
    const tags = (tagRows ?? []) as Array<{ id: string }>;
    const assignments = tags.flatMap((tag, idx) =>
      memberIds
        .filter((_, memberIdx) => memberIdx % Math.max(2, idx + 2) !== 0)
        .slice(0, 5)
        .map((memberId) => ({ tag_id: tag.id, user_id: memberId, assigned_by: actorId })),
    );
    if (assignments.length) {
      const { error: assignmentError } = await admin
        .from("club_member_tag_assignments")
        .upsert(assignments, { onConflict: "tag_id,user_id" });
      if (assignmentError && assignmentError.code !== "23505") throw assignmentError;
    }
  } catch (tagError) {
    if (!isMissingRelationError(tagError)) throw tagError;
  }

  try {
    const { data: committeeRows, error: committeeError } = await admin
      .from("club_committees")
      .insert(plan.committees.map((name) => ({ club_id: clubId, name })))
      .select("id");
    if (committeeError) throw committeeError;
    const committees = (committeeRows ?? []) as Array<{ id: string }>;
    const committeeMembers = committees.flatMap((committee, idx) =>
      memberIds
        .filter((_, memberIdx) => memberIdx % 2 === idx % 2)
        .map((memberId) => ({ committee_id: committee.id, user_id: memberId, added_by: actorId })),
    );
    if (committeeMembers.length) {
      const { error } = await admin
        .from("club_committee_members")
        .upsert(committeeMembers, { onConflict: "committee_id,user_id" });
      if (error && error.code !== "23505") throw error;
    }
  } catch (committeeError) {
    if (!isMissingRelationError(committeeError)) throw committeeError;
  }

  try {
    const { data: teamRows, error: teamError } = await admin
      .from("club_teams")
      .insert(plan.teams.map((name) => ({ club_id: clubId, name })))
      .select("id");
    if (teamError) throw teamError;
    const teams = (teamRows ?? []) as Array<{ id: string }>;
    const teamMembers = teams.flatMap((team, idx) =>
      memberIds
        .filter((_, memberIdx) => memberIdx % 3 !== idx % 3)
        .map((memberId) => ({ team_id: team.id, user_id: memberId, added_by: actorId })),
    );
    if (teamMembers.length) {
      const { error } = await admin.from("club_team_members").upsert(teamMembers, { onConflict: "team_id,user_id" });
      if (error && error.code !== "23505") throw error;
    }
  } catch (teamError) {
    if (!isMissingRelationError(teamError)) throw teamError;
  }

  try {
    const volunteerRows = memberIds.slice(0, 8).flatMap((memberId, idx) => [
      {
        club_id: clubId,
        user_id: memberId,
        hours: Number((1.5 + (idx % 4) * 0.75).toFixed(2)),
        note: "Community service shift",
        service_date: dateOnlyWithOffsetDays(-(idx + 8)),
        created_by: actorId,
        updated_by: actorId,
      },
      {
        club_id: clubId,
        user_id: memberId,
        hours: Number((1 + (idx % 3) * 0.5).toFixed(2)),
        note: "Club event support",
        service_date: dateOnlyWithOffsetDays(-(idx + 2)),
        created_by: actorId,
        updated_by: actorId,
      },
    ]);
    const { error } = await admin.from("club_member_volunteer_hours").insert(volunteerRows);
    if (error) throw error;
  } catch (volunteerError) {
    if (!isMissingRelationError(volunteerError)) throw volunteerError;
  }

  try {
    const skillRows = memberIds.slice(0, 9).flatMap((memberId, idx) => [
      {
        club_id: clubId,
        user_id: memberId,
        kind: "skill",
        label: ["Public Speaking", "Planning", "Research", "Design", "Facilitation"][idx % 5],
      },
      {
        club_id: clubId,
        user_id: memberId,
        kind: "interest",
        label: ["Leadership", "Community Service", "Event Planning", "Mentoring", "Competition Prep"][idx % 5],
      },
    ]);
    const { error } = await admin.from("club_member_skills_interests").insert(skillRows);
    if (error && error.code !== "23505") throw error;
  } catch (skillsError) {
    if (!isMissingRelationError(skillsError)) throw skillsError;
  }

  try {
    const availabilityRows = memberIds.slice(0, 8).flatMap((memberId, idx) => [
      {
        club_id: clubId,
        user_id: memberId,
        day_of_week: ((idx % 5) + 1) as 1 | 2 | 3 | 4 | 5,
        time_start: "15:30:00",
        time_end: "17:00:00",
      },
      {
        club_id: clubId,
        user_id: memberId,
        day_of_week: ((idx % 5) + 1) as 1 | 2 | 3 | 4 | 5,
        time_start: "18:00:00",
        time_end: "19:00:00",
      },
    ]);
    const { error } = await admin.from("club_member_availability_slots").insert(availabilityRows);
    if (error) throw error;
  } catch (availabilityError) {
    if (!isMissingRelationError(availabilityError)) throw availabilityError;
  }

  try {
    const noteRows = uniqueSlugs.slice(1, 4).map((slug, idx) => ({
      club_id: clubId,
      user_id: personIdBySlug(idsBySlug, slug),
      body:
        idx === 0
          ? "Reliable contributor and strong communicator in planning meetings."
          : idx === 1
            ? "Great with follow-through; consider mentoring newer members."
            : "Good initiative during events; continue coaching on delegation.",
      updated_by: actorId,
    }));
    const { error } = await admin.from("club_member_officer_notes").upsert(noteRows, { onConflict: "club_id,user_id" });
    if (error) throw error;
  } catch (notesError) {
    if (!isMissingRelationError(notesError)) throw notesError;
  }
}

async function seedDues(
  admin: SupabaseClient,
  clubId: string,
  plan: ClubPlan,
  idsBySlug: Map<string, string>,
): Promise<void> {
  const actorId = personIdBySlug(idsBySlug, plan.president);
  const uniqueMemberSlugs = Array.from(new Set([plan.president, ...plan.officers, ...plan.members]));
  const memberIds = uniqueMemberSlugs.map((slug) => personIdBySlug(idsBySlug, slug));

  try {
    const { error: settingsError } = await admin.from("club_dues_settings").upsert(
      {
        club_id: clubId,
        label: plan.duesLabel,
        amount_cents: plan.duesAmountCents,
        due_date: dateOnlyWithOffsetDays(plan.duesDueDateOffsetDays),
        currency: "USD",
        updated_by: actorId,
      },
      { onConflict: "club_id" },
    );
    if (settingsError) throw settingsError;
  } catch (settingsError) {
    if (!isMissingRelationError(settingsError)) throw settingsError;
  }

  try {
    const statuses: Array<"paid" | "unpaid" | "partial" | "waived" | "exempt"> = [
      "paid",
      "unpaid",
      "partial",
      "waived",
      "exempt",
    ];
    const duesRows = memberIds.map((memberId, idx) => ({
      club_id: clubId,
      user_id: memberId,
      status: statuses[idx % statuses.length],
      notes:
        statuses[idx % statuses.length] === "unpaid"
          ? "Past due - follow up needed."
          : statuses[idx % statuses.length] === "partial"
            ? "Partial payment received; remainder pending."
            : statuses[idx % statuses.length] === "waived"
              ? "Officer-approved waiver."
              : statuses[idx % statuses.length] === "exempt"
                ? "Exempt this term."
                : "Paid in full.",
      updated_by: actorId,
    }));
    const { error: duesError } = await admin.from("club_member_dues").upsert(duesRows, {
      onConflict: "club_id,user_id",
    });
    if (duesError) throw duesError;
  } catch (duesError) {
    if (!isMissingRelationError(duesError)) throw duesError;
  }
}

async function seedAuditLogSamples(
  admin: SupabaseClient,
  clubId: string,
  plan: ClubPlan,
  idsBySlug: Map<string, string>,
): Promise<void> {
  const actorId = personIdBySlug(idsBySlug, plan.president);
  const mimiId = personIdBySlug(idsBySlug, "mimi");
  const { data: officerRole } = await admin
    .from("club_roles")
    .select("id")
    .eq("club_id", clubId)
    .eq("name", "Officer")
    .maybeSingle();

  const rows = [
    {
      club_id: clubId,
      actor_id: actorId,
      action: "role.assigned",
      target_user_id: mimiId,
      target_role_id: (officerRole?.id as string | undefined) ?? null,
      metadata: { role_name: plan.name === "Model UN Club" ? "Officer" : "Member" },
      created_at: nowIsoWithOffsetDays(-14, 12),
    },
    {
      club_id: clubId,
      actor_id: actorId,
      action: "members.invited",
      target_user_id: null,
      target_role_id: null,
      metadata: { source: "club fair interest list" },
      created_at: nowIsoWithOffsetDays(-8, 10),
    },
  ];
  const { error } = await admin.from("club_audit_logs").insert(rows);
  if (error) throw error;
}

async function markAlumniSamples(
  admin: SupabaseClient,
  clubIdsBySlug: Map<string, string>,
  idsBySlug: Map<string, string>,
): Promise<void> {
  const alumniUpdates: Array<{ clubSlug: string; memberSlug: string }> = [
    { clubSlug: "spanish-honor-society", memberSlug: "nora" },
    { clubSlug: "fbla", memberSlug: "sophia" },
  ];

  for (const entry of alumniUpdates) {
    const clubId = clubIdsBySlug.get(entry.clubSlug);
    if (!clubId) continue;
    const userId = personIdBySlug(idsBySlug, entry.memberSlug);

    const { error: memberUpdateError } = await admin
      .from("club_members")
      .update({ membership_status: "alumni", role: "member" })
      .eq("club_id", clubId)
      .eq("user_id", userId);
    if (memberUpdateError) throw memberUpdateError;

    const { error: roleCleanupError } = await admin
      .from("member_roles")
      .delete()
      .eq("club_id", clubId)
      .eq("user_id", userId);
    if (roleCleanupError) throw roleCleanupError;
  }
}

async function main(): Promise<void> {
  assertSafeToRun();
  assertRemoteTargetOptIn();

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  if (!url || !serviceKey) {
    throw new Error("Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.");
  }
  if (!MIMI_PASSWORD) {
    throw new Error("MIMI_DEMO_PASSWORD resolved to an empty string.");
  }

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  console.log("Resetting designated Mimi demo clubs...");
  await deleteDemoClubs(admin);

  console.log("Removing designated Mimi demo users (for clean idempotent rerun)...");
  await deleteDesignatedUsers(admin);

  console.log("Creating demo auth users and profiles...");
  const idsBySlug = await createUsersAndProfiles(admin);
  console.log(`  Users ready: ${idsBySlug.size}`);

  const clubIdsBySlug = new Map<string, string>();
  for (const plan of CLUBS) {
    const presidentId = personIdBySlug(idsBySlug, plan.president);

    const { data: club, error: clubError } = await admin
      .from("clubs")
      .insert({
        name: plan.name,
        description: plan.description,
        join_code: plan.joinCode,
        created_by: presidentId,
        status: "active",
        require_join_approval: plan.requireJoinApproval,
      })
      .select("id")
      .single();
    if (clubError) throw clubError;
    const clubId = club.id as string;
    clubIdsBySlug.set(plan.slug, clubId);

    await seedSystemRolesForClub(admin, clubId, presidentId);
    await assignRolesForClub(admin, clubId, plan, idsBySlug);

    const memberIds = Array.from(new Set([plan.president, ...plan.officers, ...plan.members])).map((slug) =>
      personIdBySlug(idsBySlug, slug),
    );

    await seedAnnouncements(admin, clubId, plan, idsBySlug, memberIds);
    await seedEventsTasksAndNotifications(admin, clubId, plan, idsBySlug, memberIds);
    await seedMemberMetadata(admin, clubId, plan, idsBySlug);
    await seedDues(admin, clubId, plan, idsBySlug);
    await seedAuditLogSamples(admin, clubId, plan, idsBySlug);

    console.log(`  Seeded ${plan.name}`);
  }

  await markAlumniSamples(admin, clubIdsBySlug, idsBySlug);

  console.log("\nMimi demo seed complete.");
  console.log(`Login email: ${MIMI_EMAIL}`);
  console.log(`Login password: ${MIMI_PASSWORD}`);
  console.log("Supporting account password:", SUPPORTING_PASSWORD);
  console.log("Join codes:", CLUBS.map((c) => c.joinCode).join(", "));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

