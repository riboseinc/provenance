import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app";
import type { Env } from "../src/env";
import { makeHttpFixture } from "./fixtures";

function collectTsFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      files.push(...collectTsFiles(full));
    } else if (full.endsWith(".ts")) {
      files.push(full);
    }
  }
  return files;
}

describe("instance-agnostic acceptance", () => {
  it("contains zero hardcoded ribose.com or instance-specific identifiers in src/", () => {
    const srcFiles = collectTsFiles(join(process.cwd(), "src"));
    expect(srcFiles.length).toBeGreaterThan(0);

    for (const file of srcFiles) {
      const content = readFileSync(file, "utf8");
      expect(content).not.toMatch(/ribose\.com/i);
      expect(content).not.toMatch(/riboseinc/i);
      expect(content).not.toMatch(/ribosei/i);
    }
  });

  it("boots a second independent instance strictly from configuration", async () => {
    const { fetcher } = makeHttpFixture();
    const secondInstanceEnv: Env = {
      INSTANCE_NAME: "Northwind Trust Portal",
      INSTANCE_HOST: "trust.northwind.invalid",
      POLICY_ORG_NAME: "Northwind Engineering",
      POLICY_SUPPLIER_NAME: "Northwind Engineering",
      POLICY_PURL_NAMESPACE: "northwind",
      SUPPORT_CONTACT_URL: "https://northwind.invalid/support",
      CATALOG_JSON: JSON.stringify([
        {
          repo: "northwind/core",
          name: "northwind-core",
          tier: "A",
          releaseStream: "2.x",
          description: "Northwind core library",
        },
      ]),
    };

    const app = createApp(secondInstanceEnv, { fetcher });

    const health = await app.fetch(new Request("https://trust.northwind.invalid/healthz"));
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({
      ok: true,
      instance: "Northwind Trust Portal",
      host: "trust.northwind.invalid",
      trackedPackages: 1,
    });

    const home = await app.fetch(new Request("https://trust.northwind.invalid/"));
    expect(home.status).toBe(200);
    const homeHtml = await home.text();
    expect(homeHtml).toContain("Northwind Trust Portal");
    expect(homeHtml).toContain("Northwind Engineering");
    expect(homeHtml).toContain("northwind/core");
    expect(homeHtml).not.toContain("Example Provenance");

    const policy = await app.fetch(new Request("https://trust.northwind.invalid/policy"));
    expect(policy.status).toBe(200);
    const policyHtml = await policy.text();
    expect(policyHtml).toContain("Northwind Engineering");
    expect(policyHtml).toContain("northwind");
    expect(policyHtml).toContain("https://northwind.invalid/support");
  });
});
