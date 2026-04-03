import {
  DEFAULT_PILOT_EMAIL,
  DEFAULT_PILOT_PASSWORD,
  ROSTER_PASSWORD,
} from "./constants";

export type RosterSlug =
  | "pilot"
  | "elena"
  | "marcus"
  | "james"
  | "priya"
  | "sophie"
  | "tessa"
  | "diego";

export type RosterEntry = {
  slug: RosterSlug;
  email: string;
  password: string;
  fullName: string;
};

/** Fixed roster (pilot email/password overridable via env in run.ts). */
export function buildRoster(pilotEmail: string, pilotPassword: string): RosterEntry[] {
  return [
    { slug: "pilot", email: pilotEmail, password: pilotPassword, fullName: "Jordan Park" },
    { slug: "elena", email: "showcase.elena@clubhub.local", password: ROSTER_PASSWORD, fullName: "Elena Okonkwo" },
    { slug: "marcus", email: "showcase.marcus@clubhub.local", password: ROSTER_PASSWORD, fullName: "Marcus Chen" },
    { slug: "james", email: "showcase.james@clubhub.local", password: ROSTER_PASSWORD, fullName: "James Rivera" },
    { slug: "priya", email: "showcase.priya@clubhub.local", password: ROSTER_PASSWORD, fullName: "Priya Nair" },
    { slug: "sophie", email: "showcase.sophie@clubhub.local", password: ROSTER_PASSWORD, fullName: "Sophie Brennan" },
    { slug: "tessa", email: "showcase.tessa@clubhub.local", password: ROSTER_PASSWORD, fullName: "Tessa Morales" },
    { slug: "diego", email: "showcase.diego@clubhub.local", password: ROSTER_PASSWORD, fullName: "Diego Alvarez" },
  ];
}

export { DEFAULT_PILOT_EMAIL, DEFAULT_PILOT_PASSWORD };
