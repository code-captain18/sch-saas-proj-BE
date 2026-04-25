import type express from "express";
import { createClient, type RedisClientType } from "redis";

type LimiterState = {
    count: number;
    resetAt: number;
    blockedUntil?: number;
};

type ConsumeOptions = {
    limit: number;
    windowMs: number;
    blockMs?: number;
};

type ConsumeResult = {
    allowed: boolean;
    retryAfterSeconds: number;
};

const limiterStore = new Map<string, LimiterState>();
const cooldownStore = new Map<string, number>();

const redisUrl = process.env.REDIS_URL?.trim();
let redisClient: RedisClientType | null = null;
let redisConnected = false;

if (redisUrl) {
    redisClient = createClient({ url: redisUrl });
    redisClient.on("error", (err) => {
        redisConnected = false;
        console.warn("[OTP Security] Redis error, using in-memory fallback:", err instanceof Error ? err.message : err);
    });

    redisClient
        .connect()
        .then(() => {
            redisConnected = true;
            console.log("[OTP Security] Redis limiter enabled");
        })
        .catch((err) => {
            redisConnected = false;
            console.warn("[OTP Security] Failed to connect Redis, using in-memory fallback:", err instanceof Error ? err.message : err);
        });
}

function nowMs() {
    return Date.now();
}

function getRedisClient(): RedisClientType | null {
    if (!redisClient || !redisConnected) return null;
    return redisClient;
}

function cleanupExpired(key: string, state: LimiterState) {
    const now = nowMs();
    if (state.resetAt <= now && (!state.blockedUntil || state.blockedUntil <= now)) {
        limiterStore.delete(key);
    }
}

export async function consumeRateLimit(key: string, options: ConsumeOptions): Promise<ConsumeResult> {
    const client = getRedisClient();
    if (client) {
        try {
            const blockedKey = `otp:block:${key}`;
            const counterKey = `otp:count:${key}`;

            const blockedTtlMs = await client.pTTL(blockedKey);
            if (blockedTtlMs > 0) {
                return {
                    allowed: false,
                    retryAfterSeconds: Math.max(1, Math.ceil(blockedTtlMs / 1000)),
                };
            }

            const count = await client.incr(counterKey);
            if (count === 1) {
                await client.pExpire(counterKey, options.windowMs);
            }

            if (count > options.limit) {
                if (options.blockMs) {
                    await client.set(blockedKey, "1", {
                        PX: options.blockMs,
                    });
                    return {
                        allowed: false,
                        retryAfterSeconds: Math.max(1, Math.ceil(options.blockMs / 1000)),
                    };
                }

                const counterTtlMs = await client.pTTL(counterKey);
                return {
                    allowed: false,
                    retryAfterSeconds: Math.max(1, Math.ceil(Math.max(counterTtlMs, 1000) / 1000)),
                };
            }

            return { allowed: true, retryAfterSeconds: 0 };
        } catch {
            redisConnected = false;
        }
    }

    const now = nowMs();
    const existing = limiterStore.get(key);

    if (existing?.blockedUntil && existing.blockedUntil > now) {
        return {
            allowed: false,
            retryAfterSeconds: Math.max(1, Math.ceil((existing.blockedUntil - now) / 1000)),
        };
    }

    if (!existing || existing.resetAt <= now) {
        limiterStore.set(key, {
            count: 1,
            resetAt: now + options.windowMs,
        });
        return { allowed: true, retryAfterSeconds: 0 };
    }

    existing.count += 1;

    if (existing.count > options.limit) {
        if (options.blockMs) {
            existing.blockedUntil = now + options.blockMs;
        }
        limiterStore.set(key, existing);
        return {
            allowed: false,
            retryAfterSeconds: Math.max(
                1,
                Math.ceil(((existing.blockedUntil ?? existing.resetAt) - now) / 1000),
            ),
        };
    }

    limiterStore.set(key, existing);
    cleanupExpired(key, existing);
    return { allowed: true, retryAfterSeconds: 0 };
}

export async function consumeCooldown(key: string, cooldownMs: number): Promise<ConsumeResult> {
    const client = getRedisClient();
    if (client) {
        try {
            const cooldownKey = `otp:cooldown:${key}`;
            const setResult = await client.set(cooldownKey, "1", {
                PX: cooldownMs,
                NX: true,
            });

            if (setResult === "OK") {
                return { allowed: true, retryAfterSeconds: 0 };
            }

            const ttlMs = await client.pTTL(cooldownKey);
            return {
                allowed: false,
                retryAfterSeconds: Math.max(1, Math.ceil(Math.max(ttlMs, 1000) / 1000)),
            };
        } catch {
            redisConnected = false;
        }
    }

    const now = nowMs();
    const existing = cooldownStore.get(key);

    if (existing && existing > now) {
        return {
            allowed: false,
            retryAfterSeconds: Math.max(1, Math.ceil((existing - now) / 1000)),
        };
    }

    cooldownStore.set(key, now + cooldownMs);
    return { allowed: true, retryAfterSeconds: 0 };
}

export async function clearLimiterKey(key: string) {
    const client = getRedisClient();
    if (client) {
        try {
            await client.del([`otp:count:${key}`, `otp:block:${key}`, `otp:cooldown:${key}`]);
            return;
        } catch {
            redisConnected = false;
        }
    }

    limiterStore.delete(key);
    cooldownStore.delete(key);
}

export function getRequestIp(req: express.Request): string {
    const forwardedFor = req.headers["x-forwarded-for"];
    if (typeof forwardedFor === "string" && forwardedFor.trim()) {
        return forwardedFor.split(",")[0]!.trim();
    }

    const candidate = req.ip || req.socket?.remoteAddress || "unknown";
    return String(candidate);
}
