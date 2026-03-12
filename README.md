# ClubHub

ClubHub is a modern web app for school clubs to manage announcements, events, and member engagement in one place.

## MVP Features

- User signup, login, logout
- Protected app routes
- Create and join clubs
- Club detail page with members, announcements, and events
- Officer-only announcement and event creation
- Member RSVP (`yes` / `no` / `maybe`)
- Personalized dashboard with:
  - user clubs
  - recent announcements
  - upcoming events

## Tech Stack

- Next.js (App Router)
- TypeScript
- Tailwind CSS
- Supabase (Auth + Postgres + RLS)

## Local Development

1. Install dependencies:

```bash
npm install
```

2. Create local env file:

```bash
cp .env.example .env.local
```

3. Fill in `.env.local` values:

```bash
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
```

4. Apply schema in Supabase SQL Editor:
- Run `supabase/001_mvp_schema.sql`

5. Start dev server:

```bash
npm run dev
```

Open `http://localhost:3000`.

## Deployment (Vercel)

1. Push repo to GitHub.
2. Import project in Vercel.
3. In Vercel project settings, add Environment Variables:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
4. Set variables for `Production` (and `Preview` if desired).
5. Deploy.

## Supabase Settings Checklist

- SQL schema applied from `supabase/001_mvp_schema.sql`
- RLS enabled on app tables (included in schema file)
- Email auth provider enabled in Supabase Auth settings
- If using email confirmation, test confirmation flow in production
- API keys copied from the same Supabase project used by deployment

## Post-Deployment Smoke Test

1. Open deployed app URL.
2. Sign up a new user, then log in.
3. Create a club.
4. Join the club from another account.
5. Open club page and verify:
   - member list visible
   - officer can post announcement
   - officer can create event
   - members can RSVP
6. Open dashboard and verify:
   - clubs list
   - recent announcements
   - upcoming events

## Project Structure

```text
src/
  app/
    (app)/
      dashboard/
      clubs/
      layout.tsx
    auth/
      actions.ts
    login/
    signup/
  components/
    layout/
  lib/
    clubs/
    supabase/
supabase/
  001_mvp_schema.sql
```
