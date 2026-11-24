import { describe, expect, it } from "vitest";
import { createApp } from "../src/app";
import type { Env } from "../src/env";
import { makeFakeD1, makeFakeKv, makeHttpFixture } from "./fixtures";

function makeEnv(overrides?: Partial<Env>): Env {
  return {
    INSTANCE_NAME: "Acme Provenance",
    INSTANCE_HOST: "provenance.acme.example",
    POLICY_ORG_NAME: "Acme Software Foundation",
    POLICY_SUPPLIER_NAME: "Acme Software Foundation",
    POLICY_PURL_NAMESPACE: "acme",
    SUPPORT_CONTACT_URL: "https://acme.example/security",
    GITHUB_API_BASE: "https://github-api.example",
    OSV_API_BASE: "https://osv.example",
    CATALOG_JSON: JSON.stringify([
      {
        repo: "acme/widget",
        name: "widget",
        tier: "A",
        releaseStream: "1.x",
        description: "Acme cryptographic widget",
        osvFeedUrl: "https://feeds.example/feeds/osv.json",
        ghsaFeedUrl: "https://feeds.example/feeds/ghsa.json",
      },
      {
        repo: "acme/cli",
        name: "acme-cli",
        tier: "B",
        releaseStream: "main",
        description: "Acme CLI helper",
      },
    ]),
    DB: makeFakeD1(),
    CACHE: makeFakeKv(),
    ...overrides,
  };
}

describe("app.fetch integration", () => {
  it("renders catalog index grouped by tier and release stream", async () => {
    const { fetcher } = makeHttpFixture();
    const app = createApp(makeEnv(), { fetcher, nowMs: () => Date.UTC(2026, 10, 24) });

    const res = await app.fetch(new Request("https://provenance.acme.example/"));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Acme Provenance");
    expect(html).toContain("Tier A");
    expect(html).toContain("Tier B");
    expect(html).toContain("acme/widget");
    expect(html).toContain("1.x");
    expect(html).toContain("acme/cli");
  });

  it("renders per-release provenance page with components, licenses, attestation, OSV/GHSA, support window, and public PR attributions", async () => {
    const { fetcher, calls } = makeHttpFixture();
    const app = createApp(makeEnv(), { fetcher, nowMs: () => Date.UTC(2026, 10, 24) });

    const res = await app.fetch(
      new Request("https://provenance.acme.example/packages/acme/widget/releases/v1.2.3"),
    );
    expect(res.status).toBe(200);
    const html = await res.text();

    // Components & licenses & NOTICE
    expect(html).toContain("widget");
    expect(html).toContain("botan");
    expect(html).toContain("BSD-3-Clause");
    expect(html).toContain("BSD-2-Clause");
    expect(html).toContain("Copyright (c) 2026 Acme Software Foundation.");

    // Attestation verification command
    expect(html).toContain("gh attestation verify widget-1.2.3.tar.gz -R acme/widget");

    // Vulnerability status
    expect(html).toContain("OSV-2026-0042");

    // Support window
    expect(html).toContain("2028-11-20");
    expect(html).toContain("Active");

    // Public PR attribution (and zero portal internals/emails)
    expect(html).toContain("#101 feat: harden key derivation");
    expect(html).toContain("OCLA (Acme Corporate CLA)");
    expect(html).not.toContain("internal-999");
    expect(html).not.toContain("alice@private.example");

    // Second request hits ephemeral cache without extra upstream HTTP calls
    const callsAfterFirst = calls.length;
    const res2 = await app.fetch(
      new Request("https://provenance.acme.example/api/packages/acme/widget/releases/v1.2.3"),
    );
    expect(res2.status).toBe(200);
    expect(calls.length).toBe(callsAfterFirst);
    const json = (await res2.json()) as {
      repo: string;
      tag: string;
      vulnerabilities: { status: string };
    };
    expect(json.repo).toBe("acme/widget");
    expect(json.tag).toBe("v1.2.3");
    expect(json.vulnerabilities.status).toBe("affected");
  });

  it("renders normative estate SBOM policy page", async () => {
    const { fetcher } = makeHttpFixture();
    const app = createApp(makeEnv(), { fetcher });

    const res = await app.fetch(new Request("https://provenance.acme.example/policy"));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Normative Estate SBOM &amp; Provenance Policy");
    expect(html).toContain("SPDX 3.0");
    expect(html).toContain("CycloneDX 1.7");
    expect(html).toContain("CISA 2026 Minimum Elements");
    expect(html).toContain("SBOM Author Signature");
    expect(html).toContain("Component Dependency Relationship");
    expect(html).toContain("Acme Software Foundation");
  });

  it("fails closed on invalid configuration, 404 releases, and malformed SBOMs", async () => {
    const { fetcher } = makeHttpFixture({
      "/widget-bad.spdx.json": () => new Response("{not-json", { status: 200 }),
      "/repos/acme/bad/releases/tags/v0.0.1": () =>
        Response.json({
          tag_name: "v0.0.1",
          name: "v0.0.1",
          html_url: "https://github.com/acme/bad/releases/tag/v0.0.1",
          published_at: "2026-11-20T00:00:00Z",
          body: "",
          assets: [
            { name: "bad.spdx.json", browser_download_url: "https://assets.example/widget-bad.spdx.json", size: 10 },
          ],
        }),
      "/repos/acme/bad/pulls": () => Response.json([]),
    });

    // Invalid CATALOG_JSON -> 500 fail closed
    const badConfigApp = createApp(makeEnv({ CATALOG_JSON: "{broken" }), { fetcher });
    const badCfgRes = await badConfigApp.fetch(new Request("https://provenance.acme.example/"));
    expect(badCfgRes.status).toBe(500);

    // 404 release -> 404
    const app = createApp(makeEnv(), { fetcher });
    const notFoundRes = await app.fetch(
      new Request("https://provenance.acme.example/packages/acme/widget/releases/v9.9.9"),
    );
    expect(notFoundRes.status).toBe(404);

    // Malformed SBOM -> 502 fail closed
    const badSbomRes = await app.fetch(
      new Request("https://provenance.acme.example/packages/acme/bad/releases/v0.0.1"),
    );
    expect(badSbomRes.status).toBe(502);
  });
});
