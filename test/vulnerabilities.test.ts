import { describe, expect, it } from "vitest";
import { parseSbom } from "../src/kernel/sbom";
import { matchVulnerabilities, normalizeBasePurl } from "../src/kernel/vulnerabilities";
import { SAMPLE_CDX17, SAMPLE_GHSA_ADVISORIES, SAMPLE_OSV_ADVISORIES } from "./fixtures";

describe("kernel/vulnerabilities", () => {
  it("normalizes PURLs by stripping version, qualifiers, and subpaths", () => {
    expect(normalizeBasePurl("pkg:cargo/rnp@0.17.1?arch=x86_64#sub")).toBe("pkg:cargo/rnp");
    expect(normalizeBasePurl("pkg:generic/acme/widget@1.2.3")).toBe("pkg:generic/acme/widget");
  });

  it("matches SBOM components against OSV and GHSA advisories", () => {
    const sbom = parseSbom(SAMPLE_CDX17);
    const report = matchVulnerabilities({
      components: sbom.components,
      osvAdvisories: SAMPLE_OSV_ADVISORIES,
      ghsaAdvisories: SAMPLE_GHSA_ADVISORIES,
    });

    // botan 3.4.0 is in [3.0.0, 3.5.0) for OSV-2026-0042; widget 1.2.3 is NOT < 1.2.3 for GHSA
    expect(report.status).toBe("affected");
    expect(report.advisories).toHaveLength(1);
    expect(report.advisories[0]?.id).toBe("OSV-2026-0042");
    expect(report.advisories[0]?.severity).toBe("HIGH");
    expect(report.advisories[0]?.affectedComponents[0]).toMatchObject({
      name: "botan",
      version: "3.4.0",
      fixedVersion: "3.5.0",
    });
  });

  it("returns clean when no advisories match component versions", () => {
    const sbom = parseSbom(SAMPLE_CDX17);
    const report = matchVulnerabilities({
      components: sbom.components,
      osvAdvisories: [],
      ghsaAdvisories: SAMPLE_GHSA_ADVISORIES,
    });

    expect(report.status).toBe("clean");
    expect(report.advisories).toHaveLength(0);
  });
});
