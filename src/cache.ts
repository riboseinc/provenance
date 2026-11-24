import type { Env } from "./env";

export type CacheEntry = {
  payload: string;
  etag?: string;
};

export interface EphemeralCache {
  get(key: string): Promise<CacheEntry | undefined>;
  put(key: string, entry: CacheEntry, ttlSeconds: number): Promise<void>;
}

/**
 * Ephemeral cache backed by KV, D1, or per-isolate memory.
 * All cached data is disposable and rebuildable from upstream sources of truth.
 */
export function createEphemeralCache(env: Env, nowMs: () => number = Date.now): EphemeralCache {
  const memory = new Map<string, { entry: CacheEntry; expiresAt: number }>();

  return {
    async get(key: string): Promise<CacheEntry | undefined> {
      const now = nowMs();

      // 1. Check KV if bound
      if (env.CACHE) {
        try {
          const raw = await env.CACHE.get(key);
          if (raw) {
            const parsed = JSON.parse(raw) as CacheEntry;
            if (typeof parsed?.payload === "string") return parsed;
          }
        } catch {
          // Cache read errors degrade cleanly to cache miss
        }
      }

      // 2. Check D1 if bound
      if (env.DB) {
        try {
          const row = await env.DB.prepare(
            "SELECT payload, etag, expires_at FROM ephemeral_cache WHERE cache_key = ?1",
          )
            .bind(key)
            .first<{ payload: string; etag: string | null; expires_at: number }>();
          if (row && row.expires_at > now) {
            return {
              payload: row.payload,
              etag: row.etag ?? undefined,
            };
          }
        } catch {
          // Cache read errors degrade cleanly to cache miss
        }
      }

      // 3. Per-isolate memory fallback
      const hit = memory.get(key);
      if (hit && hit.expiresAt > now) {
        return hit.entry;
      }
      memory.delete(key);
      return undefined;
    },

    async put(key: string, entry: CacheEntry, ttlSeconds: number): Promise<void> {
      const now = nowMs();
      const expiresAt = now + ttlSeconds * 1000;
      memory.set(key, { entry, expiresAt });

      if (env.CACHE) {
        try {
          await env.CACHE.put(key, JSON.stringify(entry), {
            expirationTtl: Math.max(60, ttlSeconds),
          });
        } catch {
          // Ephemeral cache write failure is non-fatal
        }
      }

      if (env.DB) {
        try {
          await env.DB.prepare(
            `INSERT INTO ephemeral_cache (cache_key, payload, etag, expires_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(cache_key) DO UPDATE SET
               payload = excluded.payload,
               etag = excluded.etag,
               expires_at = excluded.expires_at,
               updated_at = excluded.updated_at`,
          )
            .bind(key, entry.payload, entry.etag ?? null, expiresAt, now)
            .run();
        } catch {
          // Ephemeral cache write failure is non-fatal
        }
      }
    },
  };
}
