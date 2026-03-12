# Phase 3: Supabase Setup and Schema

## 1) Create Supabase project
- Create a new Supabase project.
- In `Project Settings -> API`, copy:
  - `Project URL`
  - `anon public` key

## 2) Configure environment variables
Update `.env.local`:

```bash
NEXT_PUBLIC_SUPABASE_URL=...
NEXT_PUBLIC_SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_ROLE_KEY=... # optional for admin-only server operations
```

## 3) Apply schema
Run the SQL from `supabase/001_mvp_schema.sql` in Supabase SQL Editor.

This creates MVP tables:
- `profiles`
- `clubs`
- `club_members`
- `announcements`
- `events`
- `rsvps`

## 4) Confirm tables were created
In SQL Editor, run:

```sql
select table_name
from information_schema.tables
where table_schema = 'public'
  and table_name in ('profiles','clubs','club_members','announcements','events','rsvps')
order by table_name;
```

Expected result: all 6 table names appear.

## 5) RLS baseline included
The schema file enables RLS and adds policies so that:
- Users can read/update their own profile.
- Club members can view their clubs, announcements, events, and related RSVPs.
- Only officers can create/update/delete announcements and events.
- Users can manage their own RSVP records.
- Users can join clubs as `member`; only club creators can self-assign initial `officer` membership.

## 6) Supabase client helpers added
- Browser client: `src/lib/supabase/client.ts`
- Server client: `src/lib/supabase/server.ts`
- Env guard: `src/lib/supabase/env.ts`

## 7) Verify local setup
1. Ensure `.env.local` has your Supabase values.
2. Run `npm run dev`.
3. Visit `http://localhost:3000` and confirm app boots without env errors.
4. If you see a missing env var error, verify variable names exactly match this doc.

These are setup-only for now; auth wiring starts in Phase 4.
