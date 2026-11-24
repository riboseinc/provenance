import { describe, expect, it } from "vitest";
import { parseCycloneDx17, parseSbom, parseSpdx3 } from "../src/kernel/sbom";
import { SAMPLE_CDX17, SAMPLE_SPDX3 } from "./fixtures";

describe("kernel/sbom", () => {
  it("parses SPDX 3.0 @graph into normalized component, dependency, and license model", () => {
    const doc = parseSpdx3(SAMPLE_SPDX3);
    expect(doc.format).toBe("spdx-3.0");
    expect(doc.metadata.author).toBe("Acme Software Foundation");
    expect(doc.metadata.toolName).toBe("syft");
    expect(doc.metadata.toolVersion).toBe("1.18.1");
    expect(doc.metadata.sbomVersion).toBe(1);
    expect(doc.metadata.signatureReference).toBe("sigstore:bundle:v1.2.3");
    expect(doc.components).toHaveLength(2);
    expect(doc.components[0]?.name).toBe("widget");
    expect(doc.components[0]?.isRoot).toBe(true);
    expect(doc.components[0]?.licenses).toEqual(["BSD-3-Clause"]);
    expect(doc.components[1]?.name).toBe("botan");
    expect(doc.components[1]?.licenses).toEqual(["BSD-2-Clause"]);
    expect(doc.dependencies).toEqual([
      {
        from: "urn:spdx:pkg-widget",
        to: ["urn:spdx:pkg-botan"],
        relationship: "dependsOn",
      },
    ]);
    expect(doc.licenses).toEqual(["BSD-3-Clause", "BSD-2-Clause"]);
  });

  it("parses CycloneDX 1.7 into normalized component, dependency, and license model", () => {
    const doc = parseCycloneDx17(SAMPLE_CDX17);
    expect(doc.format).toBe("cyclonedx-1.7");
    expect(doc.metadata.author).toBe("Acme Software Foundation");
    expect(doc.metadata.toolName).toBe("syft");
    expect(doc.metadata.toolVersion).toBe("1.18.1");
    expect(doc.metadata.sbomVersion).toBe(1);
    expect(doc.metadata.generationContext).toBe("build");
    expect(doc.components).toHaveLength(2);
    expect(doc.components[0]?.isRoot).toBe(true);
    expect(doc.components[0]?.purl).toBe("pkg:generic/acme/widget@1.2.3");
    expect(doc.components[1]?.supplier).toBe("Randombit");
    expect(doc.dependencies).toHaveLength(1);
    expect(doc.licenses).toEqual(["BSD-3-Clause", "BSD-2-Clause"]);
  });

  it("auto-detects format via parseSbom and rejects malformed/unsupported payloads", () => {
    expect(parseSbom(JSON.stringify(SAMPLE_SPDX3)).format).toBe("spdx-3.0");
    expect(parseSbom(JSON.stringify(SAMPLE_CDX17)).format).toBe("cyclonedx-1.7");
    expect(() => parseSbom("{bad json")).toThrow(/Malformed SBOM JSON/);
    expect(() => parseSbom(JSON.stringify({ hello: "world" }))).toThrow(/Unsupported SBOM format/);
  });
});
