# ClubHub

ClubHub is a Next.js + Supabase web app for school clubs to manage announcements, events, and member engagement in one place.

## MVP Features

- Email signup, login, and logout
- Protected dashboard and club routes
- Create a club and join a club with a join code
- Officer/member club roles
- Club announcements
- Club events
- RSVP (`yes`, `no`, `maybe`)
- Personalized dashboard with clubs, recent announcements, and upcoming events

## Tech Stack

- Next.js 16 (App Router)
- TypeScript
- Tailwind CSS 4
- Supabase Auth + Postgres + Row Level Security
- Zod for server-side validation
- Upstash Redis for distributed rate limiting

## Required Environment Variables

Add these to `.env.local` for local development and to Vercel for preview/production:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_publishable_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
UPSTASH_REDIS_REST_URL=https://your-upstash-instance.upstash.io
UPSTASH_REDIS_REST_TOKEN=your_upstash_redis_rest_token
```

Notes:
- `SUPABASE_SERVICE_ROLE_KEY` is server-only and must never be exposed to the browser.
- Upstash env vars are required for durable rate limiting in preview/production. Without them, the app falls back to an in-memory limiter that is not reliable across serverless instances.

## Local Development

1. Install dependencies:

```bash
npm install
```

2. Create your local env file:

```bash
cp .env.example .env.local
```

3. Fill in the Supabase and Upstash values in `.env.local`.

4. Apply the database schema in the Supabase SQL Editor (or your migration workflow): run **every** numbered file under [`supabase/`](./supabase/) **in order** (`001` through the latest, e.g. `025`). The app depends on the full chain (RLS, RBAC, tasks, notifications, etc.), not only [`001_mvp_schema.sql`](./supabase/001_mvp_schema.sql).

5. Start the app:

```bash
npm run dev
```

6. Open `http://localhost:3000`.

## Deployment (Vercel)

1. Push the repo to GitHub.
2. Import the repo into Vercel.
3. Add these environment variables in Vercel Project Settings:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`
4. Add the variables to both `Preview` and `Production`.
5. Redeploy after any env change.

## Supabase Configuration Checklist

- Apply all numbered migrations in [`supabase/`](./supabase/) in order (see [docs/PRESIDENT_TEST_HANDOFF.md](./docs/PRESIDENT_TEST_HANDOFF.md) for a handoff-oriented checklist)
- Confirm core tables exist (`profiles`, `clubs`, `club_members`, `announcements`, `events`, `rsvps`, plus any added in later migrations your project uses)
- Set the correct production `Site URL`
- Add your Vercel preview and production URLs to allowed redirect URLs
- Review Auth session settings:
  - JWT lifetime
  - inactivity timeout
  - session max lifetime
  - single-session policy if desired
- Decide whether email confirmation is required and test that flow

## Post-Deploy Smoke Test

1. Sign up a new user
2. Log in and log out
3. Create a club
4. Join a club from a second account using the join code
5. Open a club page and verify:
   - officer can post announcements
   - officer can create events
   - members can RSVP
6. Open the dashboard and verify:
   - clubs render
   - recent announcements render
   - upcoming events render
7. Verify protected routes redirect unauthenticated users to `/login`

## Project Structure

```text
src/
  app/
    (app)/
      clubs/
      dashboard/
      layout.tsx
    auth/
      actions.ts
    login/
    signup/
    layout.tsx
  components/
    layout/
  lib/
    clubs/
    rate-limit.ts
    sanitize.ts
    supabase/
    validation/
supabase/
  001_mvp_schema.sql, 002_…, … (apply all numbered `.sql` in order)
middleware.ts
```
