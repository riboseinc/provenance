import { describe, expect, it } from "vitest";
import { extractPublicAttributions } from "../src/kernel/attribution";
import { SAMPLE_PRS } from "./fixtures";

describe("kernel/attribution", () => {
  it("extracts public attribution statements and strips portal internals and emails", () => {
    const records = extractPublicAttributions(SAMPLE_PRS);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      prNumber: 101,
      authorLogin: "alice",
      instrument: "OCLA (Acme Corporate CLA)",
      attributionStatement: "Contribution by @alice covered under Acme Corporate CLA.",
    });

    const serialized = JSON.stringify(records);
    expect(serialized).not.toContain("internal-999");
    expect(serialized).not.toContain("alice@private.example");
  });

  it("ignores unmerged pull requests", () => {
    const unmerged = [{ ...SAMPLE_PRS[0]!, mergedAt: "" }];
    expect(extractPublicAttributions(unmerged)).toEqual([]);
  });
});
