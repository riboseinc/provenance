import type { EphemeralCache } from "./cache";
import type { AppConfig } from "./config";
import type { PublicPrRecord } from "./kernel/types";

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export type GitHubReleaseAsset = {
  name: string;
  browser_download_url: string;
  size: number;
  content_type?: string;
};

export type GitHubRelease = {
  tag_name: string;
  name: string | null;
  html_url: string;
  published_at: string | null;
  body: string | null;
  assets: GitHubReleaseAsset[];
};

export class UpstreamError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "UpstreamError";
  }
}

const RELEASE_CACHE_TTL_SEC = 300;
const ASSET_CACHE_TTL_SEC = 3600;

function githubHeaders(config: AppConfig, accept = "application/vnd.github+json"): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: accept,
    "User-Agent": "provenance-worker/0.1",
  };
  if (config.githubToken) {
    headers["Authorization"] = `Bearer ${config.githubToken}`;
  }
  return headers;
}

async function fetchCachedText(params: {
  url: string;
  headers: Record<string, string>;
  cache: EphemeralCache;
  cacheKey: string;
  ttlSeconds: number;
  fetcher: FetchLike;
}): Promise<string> {
  const cached = await params.cache.get(params.cacheKey);
  if (cached) {
    return cached.payload;
  }

  const res = await params.fetcher(params.url, { headers: params.headers });
  if (res.status === 404) {
    throw new UpstreamError(404, `Resource not found at ${params.url}`);
  }
  if (!res.ok) {
    throw new UpstreamError(
      502,
      `Upstream request failed (${res.status}) for ${params.url}`,
    );
  }

  const text = await res.text();
  const etag = res.headers.get("etag") ?? undefined;
  await params.cache.put(params.cacheKey, { payload: text, etag }, params.ttlSeconds);
  return text;
}

export async function fetchReleaseByTag(params: {
  repo: string;
  tag: string;
  config: AppConfig;
  cache: EphemeralCache;
  fetcher: FetchLike;
}): Promise<GitHubRelease> {
  const url = `${params.config.githubApiBase}/repos/${params.repo}/releases/tags/${encodeURIComponent(params.tag)}`;
  const raw = await fetchCachedText({
    url,
    headers: githubHeaders(params.config),
    cache: params.cache,
    cacheKey: `gh:release:${params.repo}:${params.tag}`,
    ttlSeconds: RELEASE_CACHE_TTL_SEC,
    fetcher: params.fetcher,
  });

  try {
    return JSON.parse(raw) as GitHubRelease;
  } catch {
    throw new UpstreamError(502, `Invalid JSON returned for release ${params.repo}@${params.tag}`);
  }
}

export async function fetchReleasesList(params: {
  repo: string;
  config: AppConfig;
  cache: EphemeralCache;
  fetcher: FetchLike;
}): Promise<GitHubRelease[]> {
  const url = `${params.config.githubApiBase}/repos/${params.repo}/releases?per_page=10`;
  const raw = await fetchCachedText({
    url,
    headers: githubHeaders(params.config),
    cache: params.cache,
    cacheKey: `gh:releases:${params.repo}`,
    ttlSeconds: RELEASE_CACHE_TTL_SEC,
    fetcher: params.fetcher,
  });

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as GitHubRelease[]) : [];
  } catch {
    throw new UpstreamError(502, `Invalid JSON returned for releases of ${params.repo}`);
  }
}

export async function fetchAssetText(params: {
  assetUrl: string;
  config: AppConfig;
  cache: EphemeralCache;
  fetcher: FetchLike;
}): Promise<string> {
  return fetchCachedText({
    url: params.assetUrl,
    headers: githubHeaders(params.config, "application/octet-stream"),
    cache: params.cache,
    cacheKey: `gh:asset:${params.assetUrl}`,
    ttlSeconds: ASSET_CACHE_TTL_SEC,
    fetcher: params.fetcher,
  });
}

type RawGhPr = {
  number: number;
  title: string;
  html_url: string;
  merged_at: string | null;
  user: { login: string } | null;
};

type RawGhComment = {
  id: number;
  html_url: string;
  user: { login: string } | null;
  body: string | null;
  created_at: string;
};

/**
 * Fetch recent merged PRs and their public issue comments for public attribution extraction.
 * Only public GitHub PR/comment fields are retained.
 */
export async function fetchMergedPrAttributions(params: {
  repo: string;
  config: AppConfig;
  cache: EphemeralCache;
  fetcher: FetchLike;
  limit?: number;
}): Promise<PublicPrRecord[]> {
  const limit = params.limit ?? 10;
  const prsUrl = `${params.config.githubApiBase}/repos/${params.repo}/pulls?state=closed&sort=updated&direction=desc&per_page=${limit}`;

  const rawPrs = await fetchCachedText({
    url: prsUrl,
    headers: githubHeaders(params.config),
    cache: params.cache,
    cacheKey: `gh:pulls:${params.repo}:${limit}`,
    ttlSeconds: RELEASE_CACHE_TTL_SEC,
    fetcher: params.fetcher,
  });

  let parsedPrs: RawGhPr[];
  try {
    const data = JSON.parse(rawPrs);
    parsedPrs = Array.isArray(data) ? (data as RawGhPr[]) : [];
  } catch {
    throw new UpstreamError(502, `Invalid JSON returned for pulls of ${params.repo}`);
  }

  const merged = parsedPrs.filter((pr) => Boolean(pr.merged_at));
  const records = await Promise.all(
    merged.map(async (pr): Promise<PublicPrRecord> => {
      const commentsUrl = `${params.config.githubApiBase}/repos/${params.repo}/issues/${pr.number}/comments?per_page=30`;
      const rawComments = await fetchCachedText({
        url: commentsUrl,
        headers: githubHeaders(params.config),
        cache: params.cache,
        cacheKey: `gh:pr-comments:${params.repo}:${pr.number}`,
        ttlSeconds: RELEASE_CACHE_TTL_SEC,
        fetcher: params.fetcher,
      });

      let parsedComments: RawGhComment[] = [];
      try {
        const data = JSON.parse(rawComments);
        if (Array.isArray(data)) parsedComments = data as RawGhComment[];
      } catch {
        parsedComments = [];
      }

      return {
        number: pr.number,
        title: pr.title,
        url: pr.html_url,
        mergedAt: pr.merged_at!,
        authorLogin: pr.user?.login ?? "unknown",
        comments: parsedComments.map((c) => ({
          id: c.id,
          url: c.html_url,
          authorLogin: c.user?.login ?? "unknown",
          body: c.body ?? "",
          createdAt: c.created_at,
        })),
      };
    }),
  );

  return records;
}
