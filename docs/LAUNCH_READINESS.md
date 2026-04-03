# ClubHub launch readiness

Operational notes for moving from demo/testing to **real users**. This doc complements the codebase; some items are **your** responsibility outside Git.

---

## What the codebase already does well

- **RLS** is enabled on core tables (clubs, members, events, RSVPs, attendance, reflections, tasks, notifications, audit logs, RBAC tables). Policies evolved through migrations `001`–`021`; apply **all** migrations to production before launch.
- **Server actions** for governance, tasks, clubs, and notifications generally **check auth** and use **`hasPermission` / `hasPermission`-style RPCs** before writes. Destructive governance flows use **ordered operations** and DB triggers (e.g. last President).
- **Admin Supabase client** (`createAdminClient`) is **`server-only`** and reads the service role from **`env.server.ts`**, not from the public env module used by the browser.
- **Demo seed** refuses default runs when `NODE_ENV=production` or `VERCEL_ENV=production` unless `ALLOW_DEMO_SEED=true`, and refuses **non-loopback** Supabase URLs unless `DEMO_SEED_TARGET_OK=true`.
- **Events ICS export** route checks session + **club membership** before returning data.

---

## Changes made in this audit (high level)

1. **`DEMO_SEED_TARGET_OK`** — Demo seed against `*.supabase.co` (or any non-`localhost` / `127.0.0.1` host) requires this flag so a dev `.env` pointing at a shared project cannot wipe data accidentally.
2. **Service role env isolation** — `getSupabaseServiceRoleKey` lives in **`src/lib/supabase/env.server.ts`** (`server-only`); public URL/anon stay in **`env.ts`** for the browser client.

---

## Biggest remaining risks (honest)

| Risk | Mitigation |
|------|------------|
| **Migrations not applied** or drift between envs | Use one pipeline (e.g. Supabase CLI `db push` / linked project) for prod; never hand-edit prod schema casually. |
| **RLS policy gaps** on new tables | Any new table must ship with RLS + policies; review in PR. |
| **Service role key leak** | Never commit; never `NEXT_PUBLIC_*` it; rotate if exposed. |
| **Demo join codes / users in prod** | Do not run demo seed on prod user-facing project; remove demo data before go-live if you ever seeded there. |
| **Upstash / rate limit misconfig** | Club creation and some flows depend on Redis; monitor failures. |
| **Backups & Supabase project settings** | Enable PITR / backups in Supabase dashboard; test a restore once. |

---

## Manual actions for you (outside the repo)

1. **Production Supabase**
   - Create a **dedicated** project (or strictly separate branch) for production.
   - Apply **all** SQL migrations from `supabase/` in order.
   - Confirm **Auth** settings (site URL, redirect URLs, email templates).
   - Enable **backups** / **PITR** if on a plan that supports it.

2. **Secrets**
   - Set `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, and Upstash vars in the **hosting** dashboard (Vercel/Fly/etc.).
   - **Never** expose `SUPABASE_SERVICE_ROLE_KEY` to the client or commit it.
   - **Rotate** any key that ever appeared in a log, screenshot, or shared `.env`.

3. **Demo vs production**
   - Do **not** set `ALLOW_DEMO_SEED=true` or `DEMO_SEED_TARGET_OK=true` on production unless you are intentionally reseeding a **throwaway** project.
   - Before inviting real users, ensure no `DMO*` demo clubs or `@clubhub.test` users exist on the production project (unless you want them).

4. **Monitoring**
   - Add **error tracking** (e.g. Sentry) and **uptime** checks; not wired in this repo by default.

5. **Legal / product**
   - Privacy policy, data retention, and account deletion expectations if you owe them to users.

---

## Launch checklist (practical)

- [ ] All `supabase/*.sql` migrations applied to **production** database.
- [ ] Production env vars set; **no** service role in client or repo.
- [ ] `npm run build` passes; smoke-test login, create club, join, event RSVP, task, notification.
- [ ] Demo seed **not** run against production user project (or demo data removed).
- [ ] Supabase **Auth** URLs and **email** provider configured for your domain.
- [ ] Backups enabled; you know how to restore.
- [ ] Optional: error monitoring and log drain configured on the host.

---

## If something goes wrong

- **403 / empty data**: Often RLS or missing membership; check user is in `club_members` and policies match RBAC migrations.
- **500 on server actions**: Check server logs; validate `get_user_permissions` and related RPCs exist in DB.
- **Accidental demo seed**: Restore from backup; rotate service role if the key was compromised.
