import "server-only";

import { createHash } from "crypto";
import { headers } from "next/headers";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

type PolicyName =
  | "login"
  | "signup"
  | "clubCreate"
  | "clubJoin"
  | "announcementCreate"
  | "eventCreate"
  | "rsvpWrite";

type PolicyConfig = {
  limit: number;
  duration: `${number} ${"s" | "m" | "h" | "d"}`;
  windowMs: number;
};

type LimitResult = {
  success: boolean;
  reset: number;
  remaining: number;
  limit: number;
};

type EnforceRateLimitOptions = {
  policy: PolicyName;
  userId?: string;
  hint?: string;
};

type LocalBucket = {
  count: number;
  reset: number;
};

const RATE_LIMIT_POLICIES: Record<PolicyName, PolicyConfig> = {
  login: { limit: 5, duration: "10 m", windowMs: 10 * 60 * 1000 },
  signup: { limit: 4, duration: "30 m", windowMs: 30 * 60 * 1000 },
  clubCreate: { limit: 6, duration: "1 h", windowMs: 60 * 60 * 1000 },
  clubJoin: { limit: 12, duration: "10 m", windowMs: 10 * 60 * 1000 },
  announcementCreate: { limit: 20, duration: "10 m", windowMs: 10 * 60 * 1000 },
  eventCreate: { limit: 12, duration: "15 m", windowMs: 15 * 60 * 1000 },
  rsvpWrite: { limit: 40, duration: "5 m", windowMs: 5 * 60 * 1000 },
};

const localStore = globalThis.__clubhubRateLimitStore ?? new Map<string, LocalBucket>();
if (!globalThis.__clubhubRateLimitStore) {
  globalThis.__clubhubRateLimitStore = localStore;
}

let redisClient: Redis | null = null;
const ratelimiters = new Map<PolicyName, Ratelimit>();
let hasWarnedAboutLocalFallback = false;

function getRedisClient() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) {
    return null;
  }

  if (!redisClient) {
    redisClient = new Redis({ url, token });
  }

  return redisClient;
}

function getRatelimiter(policy: PolicyName) {
  if (ratelimiters.has(policy)) {
    return ratelimiters.get(policy)!;
  }

  const redis = getRedisClient();
  if (!redis) {
    return null;
  }

  const config = RATE_LIMIT_POLICIES[policy];
  const ratelimiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(config.limit, config.duration),
    prefix: `clubhub:${policy}`,
    analytics: false,
  });

  ratelimiters.set(policy, ratelimiter);
  return ratelimiter;
}

function hashValue(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function getClientIp(headerStore: Awaited<ReturnType<typeof headers>>) {
  const forwardedFor = headerStore.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0]?.trim() ?? null;
  }

  return (
    headerStore.get("x-real-ip") ??
    headerStore.get("cf-connecting-ip") ??
    headerStore.get("x-vercel-forwarded-for") ??
    null
  );
}

async function getIdentity({ userId, hint }: Pick<EnforceRateLimitOptions, "userId" | "hint">) {
  if (userId) {
    return hashValue(`user:${userId}`);
  }

  const headerStore = await headers();
  const ip = getClientIp(headerStore) ?? "unknown";
  const safeHint = hint ? `:${hint}` : "";

  return hashValue(`ip:${ip}${safeHint}`);
}

function localLimit(policy: PolicyName, identifier: string): LimitResult {
  const config = RATE_LIMIT_POLICIES[policy];
  const key = `${policy}:${identifier}`;
  const now = Date.now();

  const existing = localStore.get(key);
  const bucket =
    existing && existing.reset > now ? existing : { count: 0, reset: now + config.windowMs };

  bucket.count += 1;
  localStore.set(key, bucket);

  return {
    success: bucket.count <= config.limit,
    reset: bucket.reset,
    limit: config.limit,
    remaining: Math.max(0, config.limit - bucket.count),
  };
}

export async function enforceRateLimit(options: EnforceRateLimitOptions): Promise<LimitResult> {
  const identifier = await getIdentity(options);
  const ratelimiter = getRatelimiter(options.policy);

  if (!ratelimiter) {
    if (process.env.NODE_ENV === "production" && !hasWarnedAboutLocalFallback) {
      hasWarnedAboutLocalFallback = true;
      console.warn(
        "Rate limiting is using the in-memory fallback because UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN is missing.",
      );
    }

    return localLimit(options.policy, identifier);
  }

  const result = await ratelimiter.limit(identifier);

  return {
    success: result.success,
    reset: result.reset,
    remaining: result.remaining,
    limit: result.limit,
  };
}

export function getRateLimitErrorMessage() {
  return "Too many attempts. Please try again later.";
}

declare global {
  var __clubhubRateLimitStore: Map<string, LocalBucket> | undefined;
}
