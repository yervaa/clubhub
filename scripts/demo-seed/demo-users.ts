import { DEMO_EMAIL_DOMAIN } from "./constants";

export type DemoUserDef = {
  slug: string;
  fullName: string;
};

/** ~24 fictional students — emails `{slug}.demo@clubhub.test` */
export const DEMO_USERS: DemoUserDef[] = [
  { slug: "aaliyah", fullName: "Aaliyah Rahman" },
  { slug: "omar", fullName: "Omar Hassan" },
  { slug: "yunus", fullName: "Yunus Abbasi" },
  { slug: "sofia", fullName: "Sofia Nguyen" },
  { slug: "marcus", fullName: "Marcus Williams" },
  { slug: "priya", fullName: "Priya Kapoor" },
  { slug: "jordan", fullName: "Jordan Lee" },
  { slug: "emma", fullName: "Emma Lindqvist" },
  { slug: "diego", fullName: "Diego Morales" },
  { slug: "zara", fullName: "Zara Okonkwo" },
  { slug: "ethan", fullName: "Ethan Park" },
  { slug: "maya", fullName: "Maya Brooks" },
  { slug: "lucas", fullName: "Lucas Fernández" },
  { slug: "nadia", fullName: "Nadia El-Sayed" },
  { slug: "chloe", fullName: "Chloe Martens" },
  { slug: "henry", fullName: "Henry Okafor" },
  { slug: "rina", fullName: "Rina Tanaka" },
  { slug: "samir", fullName: "Samir Patel" },
  { slug: "ivy", fullName: "Ivy Campbell" },
  { slug: "noah", fullName: "Noah Ibrahim" },
  { slug: "tessa", fullName: "Tessa Volkov" },
  { slug: "malik", fullName: "Malik Johnson" },
  { slug: "elena", fullName: "Elena Rossi" },
  { slug: "kai", fullName: "Kai Nakamura" },
];

export function demoEmail(slug: string): string {
  return `${slug}.demo${DEMO_EMAIL_DOMAIN}`;
}
