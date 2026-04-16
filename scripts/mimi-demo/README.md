# Mimi Demo Seed

Creates a polished, repeatable ClubHub demo centered on Mimi.

## What it seeds

- Demo login: `mimi.demo@clubhub.app` (override via env)
- 5 clubs:
  - Spanish Honor Society
  - National Honor Society
  - Science Honor Society
  - Model UN Club
  - FBLA
- Role matrix:
  - Mimi = President in National Honor Society
  - Mimi = Officer in Model UN Club
  - Mimi = Member in the other 3 clubs
- Rich data in announcements, events, attendance, reflections, tasks, member metadata, dues, notifications, and audit history.

## Safety

- Uses existing demo safety flags:
  - `ALLOW_DEMO_SEED=true` required in production-like env
  - `DEMO_SEED_TARGET_OK=true` required when Supabase URL is non-loopback
- Deletes only designated demo clubs (by join code) and designated demo users (by email) before reseeding.
- Does **not** wipe unrelated clubs or users.

## Run

```bash
npm run seed:mimi-demo
```

For hosted Supabase targets:

```bash
ALLOW_DEMO_SEED=true DEMO_SEED_TARGET_OK=true npm run seed:mimi-demo
```

## Credentials

Defaults (override with env vars):

- `MIMI_DEMO_EMAIL=mimi.demo@clubhub.app`
- `MIMI_DEMO_PASSWORD=DemoClubHub!2026`
- Supporting demo users password: `MIMI_DEMO_SUPPORT_PASSWORD=ClubHubDemo!2026`

