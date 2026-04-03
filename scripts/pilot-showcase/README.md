# Pilot showcase seed

**Destructive:** removes **all clubs** (and cascaded data), **notifications**, **audit logs**, then **every auth user** on the project, then recreates:

- **8 accounts** (1 primary + 7 roster members with visible names)
- **3 clubs** (no “Demo” in names) with distinct announcements, events, tasks, RSVPs, attendance, reflections, notifications, and sample audit rows

The **primary** account is **President** in **Muslim Student Association**, **Officer** in **DECA**, and **Member** in **Photography Club**.

## Prerequisites

1. Apply `supabase/023_pilot_showcase_reset.sql` in the Supabase SQL editor (adds or updates `pilot_showcase_reset` RPC). If you applied an older version and see `DELETE requires a WHERE clause`, run the **whole file again** so the function uses `DELETE … WHERE true`.
2. `.env.local` with `NEXT_PUBLIC_SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` for **this** project only.

## Run

```bash
# Local Supabase (loopback URL)
ALLOW_PILOT_SHOWCASE=true npm run seed:pilot-showcase

# Hosted *.supabase.co (also set this)
ALLOW_PILOT_SHOWCASE=true PILOT_SHOWCASE_TARGET_OK=true npm run seed:pilot-showcase
```

Optional:

- `PILOT_SHOWCASE_EMAIL` — primary login email (default `showcase.pilot@clubhub.local`)
- `PILOT_SHOWCASE_PASSWORD` — primary password (default in `constants.ts`)

Roster accounts use `showcase.{elena,marcus,...}@clubhub.local` with the password in `constants.ts` (`ROSTER_PASSWORD`).

Join codes: **MSACLB**, **DECACL**, **PHOCLB**.

**Do not** run against a Supabase project that has real users you need to keep.
