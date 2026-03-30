/** Join codes for demo clubs — used for targeted reset (6+ chars, unique). */
export const DEMO_CLUB_JOIN_CODES = [
  "DMOBOT",
  "DMODEB",
  "DMOMSA",
  "DMOSTU",
  "DMOPHO",
] as const;

export const DEMO_EMAIL_DOMAIN = "@clubhub.test";

/** Single password for all demo accounts — local / seeded only. */
export const DEMO_USER_PASSWORD = "DemoClubHub!2026";

/** Require in production, or use non-production NODE_ENV. */
export const DEMO_SEED_ENV_FLAG = "ALLOW_DEMO_SEED";
