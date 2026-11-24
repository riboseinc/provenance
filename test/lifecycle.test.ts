import { describe, expect, it } from "vitest";
import { evaluateLifecycle, parseLifecycleDocument } from "../src/kernel/lifecycle";
import { SAMPLE_LIFECYCLE } from "./fixtures";

describe("kernel/lifecycle", () => {
  it("classifies active, expiring, and eol support windows deterministically", () => {
    const doc = parseLifecycleDocument(SAMPLE_LIFECYCLE);

    const active = evaluateLifecycle(doc, {
      nowMs: Date.UTC(2027, 0, 1), // 2027-01-01 vs 2028-11-20
    });
    expect(active.status).toBe("active");
    expect(active.craArticle14Compliant).toBe(true);
    expect(active.daysRemaining).toBeGreaterThan(90);

    const expiring = evaluateLifecycle(doc, {
      nowMs: Date.UTC(2028, 10, 1), // 2028-11-01 vs 2028-11-20 (19 days)
    });
    expect(expiring.status).toBe("expiring");
    expect(expiring.daysRemaining).toBe(19);
    expect(expiring.craArticle14Compliant).toBe(true);

    const eol = evaluateLifecycle(doc, {
      nowMs: Date.UTC(2028, 11, 1), // 2028-12-01 vs 2028-11-20
    });
    expect(eol.status).toBe("eol");
    expect(eol.daysRemaining).toBeLessThan(0);
    expect(eol.craArticle14Compliant).toBe(false);
  });

  it("rejects invalid calendar dates and unsupported schema versions", () => {
    expect(() =>
      parseLifecycleDocument({ ...SAMPLE_LIFECYCLE, supportUntil: "2026-02-30" }),
    ).toThrow(/Invalid calendar date/);
    expect(() =>
      parseLifecycleDocument({ ...SAMPLE_LIFECYCLE, schemaVersion: "2.0" }),
    ).toThrow(/Unsupported lifecycle.json schemaVersion/);
  });
});
