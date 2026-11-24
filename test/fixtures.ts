import type { FetchLike } from "../src/github";
import type { PublicPrRecord } from "../src/kernel/types";

export const SAMPLE_SPDX3 = {
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      type: "CreationInfo",
      spdxId: "urn:spdx:creation-info",
      specVersion: "3.0.1",
      created: "2026-11-20T12:00:00Z",
      createdBy: ["urn:spdx:org-acme"],
      createdUsing: ["urn:spdx:tool-syft"],
    },
    {
      type: "Organization",
      spdxId: "urn:spdx:org-acme",
      name: "Acme Software Foundation",
    },
    {
      type: "Tool",
      spdxId: "urn:spdx:tool-syft",
      name: "syft-1.18.1",
    },
    {
      type: "software_Sbom",
      spdxId: "urn:spdx:sbom",
      software_sbomType: ["build"],
      rootElement: ["urn:spdx:pkg-widget"],
    },
    {
      type: "Annotation",
      spdxId: "urn:spdx:ann-ver",
      statement: "sbomVersion=1",
    },
    {
      type: "Annotation",
      spdxId: "urn:spdx:ann-sig",
      statement: "sbomAuthorSignature=sigstore:bundle:v1.2.3",
    },
    {
      type: "software_Package",
      spdxId: "urn:spdx:pkg-widget",
      name: "widget",
      software_packageVersion: "1.2.3",
      software_packageUrl: "pkg:generic/acme/widget@1.2.3",
      suppliedBy: "urn:spdx:org-acme",
      verifiedUsing: [
        {
          algorithm: "sha256",
          hashValue: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      ],
    },
    {
      type: "software_Package",
      spdxId: "urn:spdx:pkg-botan",
      name: "botan",
      software_packageVersion: "3.4.0",
      software_packageUrl: "pkg:generic/botan@3.4.0",
      suppliedBy: "urn:spdx:org-acme",
      verifiedUsing: [
        {
          algorithm: "sha256",
          hashValue: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      ],
    },
    {
      type: "simplelicensing_LicenseExpression",
      spdxId: "urn:spdx:lic-bsd3",
      simplelicensing_licenseExpression: "BSD-3-Clause",
    },
    {
      type: "simplelicensing_LicenseExpression",
      spdxId: "urn:spdx:lic-bsd2",
      simplelicensing_licenseExpression: "BSD-2-Clause",
    },
    {
      type: "Relationship",
      spdxId: "urn:spdx:rel-lic-1",
      relationshipType: "hasDeclaredLicense",
      from: "urn:spdx:pkg-widget",
      to: ["urn:spdx:lic-bsd3"],
    },
    {
      type: "Relationship",
      spdxId: "urn:spdx:rel-lic-2",
      relationshipType: "hasConcludedLicense",
      from: "urn:spdx:pkg-botan",
      to: ["urn:spdx:lic-bsd2"],
    },
    {
      type: "Relationship",
      spdxId: "urn:spdx:rel-dep-1",
      relationshipType: "dependsOn",
      from: "urn:spdx:pkg-widget",
      to: ["urn:spdx:pkg-botan"],
    },
  ],
};

export const SAMPLE_CDX17 = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  version: 1,
  metadata: {
    timestamp: "2026-11-20T12:00:00Z",
    authors: [{ name: "Acme Software Foundation" }],
    lifecycles: [{ phase: "build" }],
    tools: {
      components: [{ name: "syft", version: "1.18.1" }],
    },
    properties: [
      { name: "cisa:sbom:author-signature", value: "sigstore:bundle:v1.2.3" },
    ],
    component: {
      "bom-ref": "pkg:generic/acme/widget@1.2.3",
      name: "widget",
      version: "1.2.3",
      purl: "pkg:generic/acme/widget@1.2.3",
      supplier: { name: "Acme Software Foundation" },
      hashes: [
        {
          alg: "SHA-256",
          content: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      ],
      licenses: [{ license: { id: "BSD-3-Clause" } }],
    },
  },
  components: [
    {
      "bom-ref": "pkg:generic/botan@3.4.0",
      name: "botan",
      version: "3.4.0",
      purl: "pkg:generic/botan@3.4.0",
      supplier: { name: "Randombit" },
      hashes: [
        {
          alg: "SHA-256",
          content: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      ],
      licenses: [{ expression: "BSD-2-Clause" }],
    },
  ],
  dependencies: [
    {
      ref: "pkg:generic/acme/widget@1.2.3",
      dependsOn: ["pkg:generic/botan@3.4.0"],
    },
  ],
};

export const SAMPLE_LIFECYCLE = {
  schemaVersion: "1.0",
  repository: "acme/widget",
  releaseTag: "v1.2.3",
  supportUntil: "2028-11-20",
  publishedAt: "2026-11-20T12:00:00Z",
  author: "Acme Software Foundation",
  attestation: {
    enabled: true,
    status: "attested",
  },
};

export const SAMPLE_NOTICE = `Acme Widget v1.2.3
Copyright (c) 2026 Acme Software Foundation.
Licensed under BSD-3-Clause.

Includes Botan 3.4.0 (BSD-2-Clause).
`;

export const SAMPLE_OSV_ADVISORIES = [
  {
    id: "OSV-2026-0042",
    aliases: ["CVE-2026-12345"],
    summary: "Out-of-bounds read in botan ASN.1 parser",
    database_specific: { severity: "HIGH" },
    references: [{ type: "ADVISORY", url: "https://osv.dev/vulnerability/OSV-2026-0042" }],
    affected: [
      {
        package: { purl: "pkg:generic/botan" },
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "3.0.0" }, { fixed: "3.5.0" }],
          },
        ],
      },
    ],
  },
];

export const SAMPLE_GHSA_ADVISORIES = [
  {
    ghsa_id: "GHSA-xxxx-yyyy-zzzz",
    cve_id: "CVE-2026-99999",
    summary: "Memory safety issue in widget",
    severity: "MEDIUM",
    html_url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
    vulnerabilities: [
      {
        package: { ecosystem: "generic", name: "widget" },
        vulnerable_version_range: ">= 1.0.0, < 1.2.3",
        first_patched_version: { identifier: "1.2.3" },
      },
    ],
  },
];

export const SAMPLE_PRS: PublicPrRecord[] = [
  {
    number: 101,
    title: "feat: harden key derivation",
    url: "https://github.com/acme/widget/pull/101",
    mergedAt: "2026-11-18T09:00:00Z",
    authorLogin: "alice",
    comments: [
      {
        id: 5001,
        url: "https://github.com/acme/widget/pull/101#issuecomment-5001",
        authorLogin: "cla-bot",
        createdAt: "2026-11-18T08:59:00Z",
        body: `<!-- cla-attribution: v1 -->
Instrument: OCLA (Acme Corporate CLA)
Attribution: Contribution by @alice covered under Acme Corporate CLA.
portal_id=internal-999 signatory_email=alice@private.example`,
      },
    ],
  },
];

export function makeFakeKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: (async (key: string) => store.get(key) ?? null) as KVNamespace["get"],
    put: (async (key: string, value: string) => {
      store.set(key, value);
    }) as KVNamespace["put"],
    delete: (async (key: string) => {
      store.delete(key);
    }) as KVNamespace["delete"],
    list: (async () => ({ keys: [], list_complete: true, cacheStatus: null })) as unknown as KVNamespace["list"],
    getWithMetadata: (async () => ({ value: null, metadata: null, cacheStatus: null })) as unknown as KVNamespace["getWithMetadata"],
  };
}

export function makeFakeD1(): D1Database {
  const rows = new Map<string, { payload: string; etag: string | null; expires_at: number; updated_at: number }>();
  return {
    prepare(query: string) {
      let args: unknown[] = [];
      const stmt = {
        bind(...values: unknown[]) {
          args = values;
          return stmt;
        },
        async first<T = Record<string, unknown>>() {
          if (query.includes("SELECT payload, etag, expires_at")) {
            const key = String(args[0] ?? "");
            const row = rows.get(key);
            return (row ?? null) as T | null;
          }
          return null;
        },
        async run() {
          if (query.includes("INSERT INTO ephemeral_cache")) {
            const key = String(args[0] ?? "");
            rows.set(key, {
              payload: String(args[1] ?? ""),
              etag: (args[2] as string | null) ?? null,
              expires_at: Number(args[3] ?? 0),
              updated_at: Number(args[4] ?? 0),
            });
          }
          return { success: true, meta: {} } as unknown as D1Result;
        },
        async all() {
          return { results: [], success: true, meta: {} } as unknown as D1Result;
        },
        async raw() {
          return [];
        },
      };
      return stmt as unknown as D1PreparedStatement;
    },
    async batch() {
      return [];
    },
    async exec() {
      return { count: 0, duration: 0 };
    },
    async dump() {
      return new ArrayBuffer(0);
    },
  } as unknown as D1Database;
}

export function makeHttpFixture(overrides?: Record<string, (url: URL, init?: RequestInit) => Response>) {
  const calls: Array<{ method: string; url: string }> = [];

  const routes: Record<string, (url: URL, init?: RequestInit) => Response> = {
    "/repos/acme/widget/releases": () =>
      Response.json([
        {
          tag_name: "v1.2.3",
          name: "v1.2.3",
          html_url: "https://github.com/acme/widget/releases/tag/v1.2.3",
          published_at: "2026-11-20T12:00:00Z",
          body: "Release v1.2.3",
          assets: [
            { name: "widget-1.2.3.tar.gz", browser_download_url: "https://assets.example/widget-1.2.3.tar.gz", size: 1024 },
            { name: "widget-1.2.3.spdx.json", browser_download_url: "https://assets.example/widget-1.2.3.spdx.json", size: 2048 },
            { name: "widget-1.2.3.cdx.json", browser_download_url: "https://assets.example/widget-1.2.3.cdx.json", size: 2048 },
            { name: "lifecycle.json", browser_download_url: "https://assets.example/lifecycle.json", size: 256 },
            { name: "NOTICE", browser_download_url: "https://assets.example/NOTICE", size: 128 },
          ],
        },
      ]),
    "/repos/acme/widget/releases/tags/v1.2.3": () =>
      Response.json({
        tag_name: "v1.2.3",
        name: "v1.2.3",
        html_url: "https://github.com/acme/widget/releases/tag/v1.2.3",
        published_at: "2026-11-20T12:00:00Z",
        body: "Release v1.2.3",
        assets: [
          { name: "widget-1.2.3.tar.gz", browser_download_url: "https://assets.example/widget-1.2.3.tar.gz", size: 1024 },
          { name: "widget-1.2.3.spdx.json", browser_download_url: "https://assets.example/widget-1.2.3.spdx.json", size: 2048 },
          { name: "widget-1.2.3.cdx.json", browser_download_url: "https://assets.example/widget-1.2.3.cdx.json", size: 2048 },
          { name: "lifecycle.json", browser_download_url: "https://assets.example/lifecycle.json", size: 256 },
          { name: "NOTICE", browser_download_url: "https://assets.example/NOTICE", size: 128 },
        ],
      }),
    "/widget-1.2.3.spdx.json": () => Response.json(SAMPLE_SPDX3),
    "/widget-1.2.3.cdx.json": () => Response.json(SAMPLE_CDX17),
    "/lifecycle.json": () => Response.json(SAMPLE_LIFECYCLE),
    "/NOTICE": () => new Response(SAMPLE_NOTICE, { status: 200 }),
    "/repos/acme/widget/pulls": () =>
      Response.json([
        {
          number: 101,
          title: "feat: harden key derivation",
          html_url: "https://github.com/acme/widget/pull/101",
          merged_at: "2026-11-18T09:00:00Z",
          user: { login: "alice" },
        },
      ]),
    "/repos/acme/widget/issues/101/comments": () =>
      Response.json([
        {
          id: 5001,
          html_url: "https://github.com/acme/widget/pull/101#issuecomment-5001",
          user: { login: "cla-bot" },
          created_at: "2026-11-18T08:59:00Z",
          body: `<!-- cla-attribution: v1 -->
Instrument: OCLA (Acme Corporate CLA)
Attribution: Contribution by @alice covered under Acme Corporate CLA.
portal_id=internal-999 signatory_email=alice@private.example`,
        },
      ]),
    "/feeds/osv.json": () => Response.json(SAMPLE_OSV_ADVISORIES),
    "/feeds/ghsa.json": () => Response.json(SAMPLE_GHSA_ADVISORIES),
    "/v1/querybatch": () => Response.json({ results: [{ vulns: [] }, { vulns: SAMPLE_OSV_ADVISORIES }] }),
    ...overrides,
  };

  const fetcher: FetchLike = async (input, init) => {
    const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const u = new URL(urlStr);
    calls.push({ method: init?.method ?? "GET", url: urlStr });
    const handler = routes[u.pathname];
    if (handler) {
      return handler(u, init);
    }
    return new Response("Not Found", { status: 404 });
  };

  return { fetcher, calls };
}
