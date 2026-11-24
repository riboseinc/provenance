import type { Env } from "./env";
import type { PackageTier, TrackedPackage } from "./kernel/types";

export type AppConfig = {
  instanceName: string;
  instanceHost: string;
  policyOrgName: string;
  policySupplierName: string;
  policyPurlNamespace: string;
  supportContactUrl?: string;
  githubApiBase: string;
  osvApiBase: string;
  githubToken?: string;
  catalog: TrackedPackage[];
};

const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function optStr(v: unknown): string | undefined {
  return typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
}

function isPackageTier(v: unknown): v is PackageTier {
  return v === "A" || v === "B" || v === "C";
}

function parseCatalog(raw: string | undefined): TrackedPackage[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid CATALOG_JSON configuration: ${(err as Error).message}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error("Invalid CATALOG_JSON configuration: expected a JSON array.");
  }

  return parsed.map((item, idx) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error(`Invalid CATALOG_JSON entry at index ${idx}: expected an object.`);
    }
    const rec = item as Record<string, unknown>;
    const repo = optStr(rec["repo"]);
    const name = optStr(rec["name"]);
    const tier = rec["tier"];
    const releaseStream = optStr(rec["releaseStream"]);
    const description = optStr(rec["description"]) ?? "";

    if (!repo || !REPO_PATTERN.test(repo)) {
      throw new Error(`Invalid CATALOG_JSON entry at index ${idx}: invalid repo "${String(rec["repo"] ?? "")}".`);
    }
    if (!name) {
      throw new Error(`Invalid CATALOG_JSON entry at index ${idx}: missing package name.`);
    }
    if (!isPackageTier(tier)) {
      throw new Error(`Invalid CATALOG_JSON entry at index ${idx}: tier must be "A", "B", or "C".`);
    }
    if (!releaseStream) {
      throw new Error(`Invalid CATALOG_JSON entry at index ${idx}: missing releaseStream.`);
    }

    return {
      repo,
      name,
      tier,
      releaseStream,
      description,
      osvFeedUrl: optStr(rec["osvFeedUrl"]),
      ghsaFeedUrl: optStr(rec["ghsaFeedUrl"]),
    };
  });
}

function normalizeBaseUrl(raw: string | undefined, fallback: string, label: string): string {
  const value = optStr(raw) ?? fallback;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid ${label} URL: "${value}".`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`Invalid ${label} URL protocol: "${url.protocol}".`);
  }
  return value.replace(/\/+$/, "");
}

/**
 * Parse and validate runtime environment configuration.
 * Fails closed on malformed URLs or malformed CATALOG_JSON.
 */
export function loadConfig(env: Env): AppConfig {
  const instanceName = optStr(env.INSTANCE_NAME) ?? "Release Provenance";
  const instanceHost = optStr(env.INSTANCE_HOST) ?? "localhost";
  const policyOrgName = optStr(env.POLICY_ORG_NAME) ?? instanceName;
  const policySupplierName = optStr(env.POLICY_SUPPLIER_NAME) ?? policyOrgName;
  const policyPurlNamespace = optStr(env.POLICY_PURL_NAMESPACE) ?? "example";
  const supportContactUrl = optStr(env.SUPPORT_CONTACT_URL);

  const githubApiBase = normalizeBaseUrl(
    optStr(env.GITHUB_API_BASE),
    "https://api.github.com",
    "GITHUB_API_BASE",
  );
  const osvApiBase = normalizeBaseUrl(
    optStr(env.OSV_API_BASE),
    "https://api.osv.dev",
    "OSV_API_BASE",
  );

  const catalog = parseCatalog(optStr(env.CATALOG_JSON));

  return {
    instanceName,
    instanceHost,
    policyOrgName,
    policySupplierName,
    policyPurlNamespace,
    supportContactUrl,
    githubApiBase,
    osvApiBase,
    githubToken: optStr(env.GITHUB_TOKEN),
    catalog,
  };
}
