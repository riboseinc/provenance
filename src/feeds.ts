import type { EphemeralCache } from "./cache";
import type { AppConfig } from "./config";
import type { FetchLike } from "./github";
import { UpstreamError } from "./github";
import type { SbomComponent, TrackedPackage } from "./kernel/types";

const FEED_CACHE_TTL_SEC = 600;

async function fetchJsonFeed(params: {
  url: string;
  cache: EphemeralCache;
  fetcher: FetchLike;
}): Promise<unknown[]> {
  const key = `feed:${params.url}`;
  const cached = await params.cache.get(key);
  let raw: string;

  if (cached) {
    raw = cached.payload;
  } else {
    const res = await params.fetcher(params.url, {
      headers: { Accept: "application/json", "User-Agent": "provenance-worker/0.1" },
    });
    if (!res.ok) {
      throw new UpstreamError(502, `Vulnerability feed request failed (${res.status}) for ${params.url}`);
    }
    raw = await res.text();
    await params.cache.put(key, { payload: raw }, FEED_CACHE_TTL_SEC);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new UpstreamError(502, `Malformed JSON from vulnerability feed ${params.url}`);
  }

  if (Array.isArray(parsed)) return parsed;
  if (typeof parsed === "object" && parsed !== null) {
    const rec = parsed as Record<string, unknown>;
    if (Array.isArray(rec["vulns"])) return rec["vulns"];
    if (Array.isArray(rec["advisories"])) return rec["advisories"];
  }
  return [];
}

async function queryOsvBatch(params: {
  components: SbomComponent[];
  config: AppConfig;
  cache: EphemeralCache;
  fetcher: FetchLike;
}): Promise<unknown[]> {
  const queries = params.components
    .filter((c) => Boolean(c.purl))
    .slice(0, 100)
    .map((c) => ({
      package: { purl: c.purl },
      version: c.version !== "unknown" ? c.version : undefined,
    }));

  if (queries.length === 0) return [];

  const url = `${params.config.osvApiBase}/v1/querybatch`;
  const cacheKey = `osv:batch:${queries.map((q) => `${q.package.purl}@${q.version ?? ""}`).join("|")}`;
  const cached = await params.cache.get(cacheKey);
  let raw: string;

  if (cached) {
    raw = cached.payload;
  } else {
    const res = await params.fetcher(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": "provenance-worker/0.1",
      },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) {
      throw new UpstreamError(502, `OSV querybatch failed (${res.status})`);
    }
    raw = await res.text();
    await params.cache.put(cacheKey, { payload: raw }, FEED_CACHE_TTL_SEC);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new UpstreamError(502, "Malformed JSON from OSV querybatch.");
  }

  const results = (parsed as { results?: Array<{ vulns?: unknown[] }> })?.results ?? [];
  return results.flatMap((r) => (Array.isArray(r.vulns) ? r.vulns : []));
}

export async function fetchVulnerabilityFeeds(params: {
  pkg?: TrackedPackage;
  components: SbomComponent[];
  config: AppConfig;
  cache: EphemeralCache;
  fetcher: FetchLike;
}): Promise<{ osvAdvisories: unknown[]; ghsaAdvisories: unknown[] }> {
  const osvAdvisories = params.pkg?.osvFeedUrl
    ? await fetchJsonFeed({
        url: params.pkg.osvFeedUrl,
        cache: params.cache,
        fetcher: params.fetcher,
      })
    : await queryOsvBatch({
        components: params.components,
        config: params.config,
        cache: params.cache,
        fetcher: params.fetcher,
      });

  const ghsaAdvisories = params.pkg?.ghsaFeedUrl
    ? await fetchJsonFeed({
        url: params.pkg.ghsaFeedUrl,
        cache: params.cache,
        fetcher: params.fetcher,
      })
    : [];

  return { osvAdvisories, ghsaAdvisories };
}
