/**
 * Single runtime boundary: what the Cloudflare Worker environment provides.
 * Instance configuration and secrets live in the private instance repo;
 * nothing instance-specific is compiled into application code.
 */
export type Env = {
  /** Human-readable instance title (e.g. "Acme Provenance"). */
  INSTANCE_NAME?: string;
  /** Public host name of the instance (e.g. "provenance.acme.example"). */
  INSTANCE_HOST?: string;
  /** Normative policy organization name. */
  POLICY_ORG_NAME?: string;
  /** Normative SBOM supplier identity string. */
  POLICY_SUPPLIER_NAME?: string;
  /** Normative PURL namespace convention for the instance. */
  POLICY_PURL_NAMESPACE?: string;
  /** Public security/support contact URL for CRA Article 14. */
  SUPPORT_CONTACT_URL?: string;
  /** JSON-encoded array of TrackedPackage entries. */
  CATALOG_JSON?: string;
  /** Base URL for GitHub REST API (default: https://api.github.com). */
  GITHUB_API_BASE?: string;
  /** Base URL for OSV API (default: https://api.osv.dev). */
  OSV_API_BASE?: string;
  /** Optional GitHub token for higher rate limits on public repos (secret). */
  GITHUB_TOKEN?: string;
  /** Ephemeral D1 database binding (rebuildable cache only). */
  DB?: D1Database;
  /** Ephemeral KV namespace binding (rebuildable cache only). */
  CACHE?: KVNamespace;

  [key: string]: unknown;
};
