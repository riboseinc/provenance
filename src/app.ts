import { Hono } from "hono";
import { createEphemeralCache } from "./cache";
import { loadConfig, type AppConfig } from "./config";
import type { Env } from "./env";
import { fetchVulnerabilityFeeds } from "./feeds";
import {
  fetchAssetText,
  fetchMergedPrAttributions,
  fetchReleaseByTag,
  fetchReleasesList,
  UpstreamError,
  type FetchLike,
} from "./github";
import {
  buildAttestationVerification,
  evaluateLifecycle,
  extractPublicAttributions,
  matchVulnerabilities,
  parseLifecycleDocument,
  parseSbom,
} from "./kernel";
import type { SbomDocument } from "./kernel/types";
import { renderCatalogPage } from "./views/catalog";
import { renderErrorPage } from "./views/error";
import { renderPackageReleasesPage } from "./views/package";
import { renderPolicyPage } from "./views/policy";
import { renderReleasePage, type ReleaseViewModel } from "./views/release";

export type AppDeps = {
  fetcher?: FetchLike;
  nowMs?: () => number;
};

const REPO_SEGMENT_PATTERN = /^[A-Za-z0-9_.-]+$/;

function validateRepoParam(owner: string, repo: string): string {
  if (!REPO_SEGMENT_PATTERN.test(owner) || !REPO_SEGMENT_PATTERN.test(repo)) {
    throw new UpstreamError(400, "Invalid repository identifier.");
  }
  return `${owner}/${repo}`;
}

async function buildReleaseViewModel(params: {
  repo: string;
  tag: string;
  config: AppConfig;
  env: Env;
  fetcher: FetchLike;
  nowMs: () => number;
}): Promise<ReleaseViewModel> {
  const cache = createEphemeralCache(params.env, params.nowMs);
  const release = await fetchReleaseByTag({
    repo: params.repo,
    tag: params.tag,
    config: params.config,
    cache,
    fetcher: params.fetcher,
  });

  const spdxAssets = release.assets.filter((a) => a.name.endsWith(".spdx.json"));
  const cdxAssets = release.assets.filter((a) => a.name.endsWith(".cdx.json"));
  const lifecycleAsset = release.assets.find((a) => a.name === "lifecycle.json");
  const noticeAsset = release.assets.find((a) => a.name === "NOTICE");

  const [sbomPayloads, lifecycleRaw, noticeText, prRecords] = await Promise.all([
    Promise.all(
      [...spdxAssets, ...cdxAssets].map((a) =>
        fetchAssetText({
          assetUrl: a.browser_download_url,
          config: params.config,
          cache,
          fetcher: params.fetcher,
        }),
      ),
    ),
    lifecycleAsset
      ? fetchAssetText({
          assetUrl: lifecycleAsset.browser_download_url,
          config: params.config,
          cache,
          fetcher: params.fetcher,
        })
      : Promise.resolve(undefined),
    noticeAsset
      ? fetchAssetText({
          assetUrl: noticeAsset.browser_download_url,
          config: params.config,
          cache,
          fetcher: params.fetcher,
        })
      : Promise.resolve(undefined),
    fetchMergedPrAttributions({
      repo: params.repo,
      config: params.config,
      cache,
      fetcher: params.fetcher,
    }),
  ]);

  const sboms: SbomDocument[] = [];
  for (const raw of sbomPayloads) {
    try {
      sboms.push(parseSbom(raw));
    } catch (err) {
      throw new UpstreamError(502, `Invalid SBOM asset: ${(err as Error).message}`);
    }
  }

  let lifecycle;
  let attestation;
  if (lifecycleRaw) {
    try {
      const parsedLifecycle = parseLifecycleDocument(lifecycleRaw);
      lifecycle = evaluateLifecycle(parsedLifecycle, { nowMs: params.nowMs() });
      const artifactNames = release.assets
        .filter(
          (a) =>
            !a.name.endsWith(".spdx.json") &&
            !a.name.endsWith(".cdx.json") &&
            a.name !== "lifecycle.json" &&
            a.name !== "NOTICE",
        )
        .map((a) => a.name);
      attestation = buildAttestationVerification({
        repository: parsedLifecycle.repository,
        releaseTag: parsedLifecycle.releaseTag,
        status: parsedLifecycle.attestation.status,
        artifactNames,
      });
    } catch (err) {
      throw new UpstreamError(502, `Invalid lifecycle.json asset: ${(err as Error).message}`);
    }
  }

  const allComponents = sboms[0]?.components ?? [];
  const trackedPkg = params.config.catalog.find((p) => p.repo === params.repo);
  const feeds = await fetchVulnerabilityFeeds({
    pkg: trackedPkg,
    components: allComponents,
    config: params.config,
    cache,
    fetcher: params.fetcher,
  });

  const vulnerabilities = matchVulnerabilities({
    components: allComponents,
    osvAdvisories: feeds.osvAdvisories,
    ghsaAdvisories: feeds.ghsaAdvisories,
  });

  const attributions = extractPublicAttributions(prRecords);

  return {
    repo: params.repo,
    tag: release.tag_name,
    release,
    lifecycle,
    sboms,
    noticeText,
    attestation,
    vulnerabilities,
    attributions,
  };
}

export function createApp(env: Env, deps?: AppDeps): Hono {
  const app = new Hono();
  const fetcher: FetchLike = deps?.fetcher ?? ((input, init) => fetch(input, init));
  const nowMs: () => number = deps?.nowMs ?? Date.now;

  // Fail-closed config validation middleware
  let config: AppConfig;
  try {
    config = loadConfig(env);
  } catch (err) {
    const message = (err as Error).message;
    app.all("*", (c) =>
      c.json({ error: "Configuration error", detail: message }, 500),
    );
    return app;
  }

  app.get("/healthz", (c) =>
    c.json({
      ok: true,
      instance: config.instanceName,
      host: config.instanceHost,
      trackedPackages: config.catalog.length,
      cache: {
        d1: Boolean(env.DB),
        kv: Boolean(env.CACHE),
      },
    }),
  );

  app.get("/", (c) => {
    const accept = c.req.header("accept") ?? "";
    if (accept.includes("application/json")) {
      return c.json({
        instance: config.instanceName,
        host: config.instanceHost,
        catalog: config.catalog,
      });
    }
    return c.html(renderCatalogPage(config));
  });

  app.get("/api/catalog", (c) =>
    c.json({
      instance: config.instanceName,
      host: config.instanceHost,
      catalog: config.catalog,
    }),
  );

  app.get("/policy", (c) => c.html(renderPolicyPage(config)));

  app.get("/packages/:owner/:repo", async (c) => {
    const repo = validateRepoParam(c.req.param("owner"), c.req.param("repo"));
    const cache = createEphemeralCache(env, nowMs);
    const releases = await fetchReleasesList({ repo, config, cache, fetcher });
    const pkg = config.catalog.find((p) => p.repo === repo);
    return c.html(renderPackageReleasesPage({ repo, pkg, releases, config }));
  });

  app.get("/packages/:owner/:repo/releases/:tag", async (c) => {
    const repo = validateRepoParam(c.req.param("owner"), c.req.param("repo"));
    const tag = c.req.param("tag");
    const vm = await buildReleaseViewModel({
      repo,
      tag,
      config,
      env,
      fetcher,
      nowMs,
    });
    return c.html(renderReleasePage(vm, config));
  });

  app.get("/api/packages/:owner/:repo/releases/:tag", async (c) => {
    const repo = validateRepoParam(c.req.param("owner"), c.req.param("repo"));
    const tag = c.req.param("tag");
    const vm = await buildReleaseViewModel({
      repo,
      tag,
      config,
      env,
      fetcher,
      nowMs,
    });
    return c.json({
      repo: vm.repo,
      tag: vm.tag,
      lifecycle: vm.lifecycle,
      attestation: vm.attestation,
      vulnerabilities: vm.vulnerabilities,
      sboms: vm.sboms,
      attributions: vm.attributions,
    });
  });

  app.notFound((c) => {
    if (c.req.path.startsWith("/api/")) {
      return c.json({ error: "Not found" }, 404);
    }
    return c.html(
      renderErrorPage({
        status: 404,
        title: "Not Found",
        message: "The requested provenance record does not exist.",
        config,
      }),
      404,
    );
  });

  app.onError((err, c) => {
    const status = err instanceof UpstreamError ? err.status : 500;
    const title = status === 404 ? "Not Found" : status === 400 ? "Bad Request" : "Upstream Error";
    const message = err instanceof UpstreamError ? err.message : "An internal error occurred.";

    if (c.req.path.startsWith("/api/")) {
      return c.json({ error: title, detail: message }, status as 400 | 404 | 500 | 502);
    }
    return c.html(
      renderErrorPage({
        status,
        title,
        message,
        config,
      }),
      status as 400 | 404 | 500 | 502,
    );
  });

  return app;
}
