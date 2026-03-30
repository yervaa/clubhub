/**
 * Demo / test data seeder for ClubHub.
 *
 * Usage:
 *   npx tsx scripts/demo-seed/run.ts           # reset demo clubs + reseed
 *   npx tsx scripts/demo-seed/run.ts --no-reset # only seed (fails if join codes exist)
 *
 * Requires .env.local: NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
 * Safety: refuses production unless ALLOW_DEMO_SEED=true
 */

import path from "path";
import { config } from "dotenv";
import { createClient } from "@supabase/supabase-js";
import { DEMO_SEED_ENV_FLAG } from "./constants";
import { resetDemoData } from "./reset";
import { createDemoAuthUsers, seedDemoDataset } from "./seed";

config({ path: path.resolve(process.cwd(), ".env.local") });
config({ path: path.resolve(process.cwd(), ".env") });

function assertSafeToRun(): void {
  const explicit = process.env[DEMO_SEED_ENV_FLAG] === "true";
  const vercelProd = process.env.VERCEL_ENV === "production";
  const nodeProd = process.env.NODE_ENV === "production";

  if (!explicit && (vercelProd || nodeProd)) {
    throw new Error(
      `Refused: demo seed is blocked in production. Set ${DEMO_SEED_ENV_FLAG}=true only when you intentionally target this environment.`,
    );
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const noReset = args.includes("--no-reset");

  assertSafeToRun();

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();

  if (!url || !serviceKey) {
    throw new Error("Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY (use service role, not anon).");
  }

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  if (!noReset) {
    console.log("Removing previous demo clubs and *.demo@clubhub.test users…");
    const { clubsRemoved, usersRemoved } = await resetDemoData(admin);
    console.log(`  Deleted ${clubsRemoved} demo club(s), ${usersRemoved} demo user(s).`);
  }

  console.log("Creating demo auth users + profiles…");
  const userIds = await createDemoAuthUsers(admin);
  console.log(`  ${userIds.size} users ready.`);

  console.log("Seeding clubs, RBAC, events, tasks, notifications, audit…");
  await seedDemoDataset(admin, userIds);

  console.log("\nDone. Log in with any *.{slug}.demo@clubhub.test — password in scripts/demo-seed/README.md");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
