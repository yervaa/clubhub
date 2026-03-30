/**
 * Static plans for demo clubs — indices refer to DEMO_USERS order in demo-users.ts
 * (0 aaliyah, 1 omar, 2 yunus, …).
 */
export type ClubPlan = {
  joinCode: string;
  name: string;
  description: string;
  /** DEMO_USERS index — club.created_by + President */
  presidentIndex: number;
  /** Legacy officer + Officer RBAC (indices) */
  officerIndices: number[];
  /** Legacy member (indices) */
  memberIndices: number[];
  /** Optional custom roles after system seed */
  customRoles?: Array<{
    name: string;
    description: string;
    userIndex: number;
    permissionKeys: string[];
  }>;
};

export const CLUB_PLANS: ClubPlan[] = [
  {
    joinCode: "DMOBOT",
    name: "Demo Robotics Club",
    description:
      "Build season for FIRST Tech Challenge: mechanical, programming, outreach, and judging prep. Lab meets Tue/Thu after school.",
    presidentIndex: 0,
    officerIndices: [1, 4, 6],
    memberIndices: [2, 3, 5, 7, 8, 9, 10, 11],
    customRoles: [
      {
        name: "Treasurer",
        description: "Budget, reimbursements, and competition fees.",
        userIndex: 4,
        permissionKeys: [
          "members.view",
          "insights.view",
          "tasks.view",
          "tasks.create",
          "announcements.create",
        ],
      },
      {
        name: "Build Captain",
        description: "Robot design priorities and pit checklist.",
        userIndex: 6,
        permissionKeys: [
          "members.view",
          "events.create",
          "events.edit",
          "tasks.view",
          "tasks.assign",
        ],
      },
    ],
  },
  {
    joinCode: "DMODEB",
    name: "Demo Debate Club",
    description:
      "Public Forum and Lincoln–Douglas practice, tournament travel, and judge feedback nights. New members always welcome.",
    presidentIndex: 1,
    officerIndices: [3, 12, 14],
    memberIndices: [0, 2, 5, 13, 15, 16, 17, 18],
    customRoles: [
      {
        name: "Tournament Director",
        description: "Registers teams, hotels, and round schedules.",
        userIndex: 12,
        permissionKeys: ["members.view", "events.create", "events.edit", "tasks.view", "tasks.create"],
      },
    ],
  },
  {
    joinCode: "DMOMSA",
    name: "Demo Muslim Student Association",
    description:
      "Weekly halaqa, Ramadan programming, interfaith panels, and community service. Open to allies and new Muslims.",
    presidentIndex: 5,
    officerIndices: [2, 19, 20],
    memberIndices: [0, 1, 3, 7, 8, 21, 22, 23],
    customRoles: [
      {
        name: "Social Chair",
        description: "Eid events, fundraisers, and room setup.",
        userIndex: 19,
        permissionKeys: [
          "members.view",
          "announcements.create",
          "events.create",
          "tasks.view",
          "tasks.assign",
        ],
      },
    ],
  },
  {
    joinCode: "DMOSTU",
    name: "Demo Student Council",
    description:
      "School spirit, class reps, budget requests, and dance/committee logistics. Meetings every Wednesday lunch.",
    presidentIndex: 7,
    officerIndices: [8, 9, 10],
    memberIndices: [2, 11, 13, 14, 15, 16, 17, 18],
    customRoles: [
      {
        name: "Secretary",
        description: "Agendas, minutes, and follow-up tasks.",
        userIndex: 9,
        permissionKeys: [
          "members.view",
          "announcements.create",
          "announcements.edit",
          "tasks.view",
          "tasks.create",
        ],
      },
    ],
  },
  {
    joinCode: "DMOPHO",
    name: "Demo Photography Club",
    description:
      "Portrait workshops, yearbook support, sports sidelines, and quarterly gallery nights. Borrow gear from the cabinet.",
    presidentIndex: 11,
    officerIndices: [13, 21],
    memberIndices: [3, 4, 6, 12, 20, 22, 23, 0],
    customRoles: [
      {
        name: "Equipment Manager",
        description: "Checkout log, lens kits, and SD cards.",
        userIndex: 21,
        permissionKeys: ["members.view", "tasks.view", "tasks.edit", "tasks.assign"],
      },
    ],
  },
];
