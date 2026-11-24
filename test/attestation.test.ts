import { describe, expect, it } from "vitest";
import { buildAttestationVerification } from "../src/kernel/attestation";

describe("kernel/attestation", () => {
  it("generates gh attestation verify commands when attested", () => {
    const res = buildAttestationVerification({
      repository: "acme/widget",
      releaseTag: "v1.2.3",
      status: "attested",
      artifactNames: ["widget-1.2.3.tar.gz"],
    });
    expect(res.status).toBe("attested");
    expect(res.commands).toEqual([
      {
        artifactName: "widget-1.2.3.tar.gz",
        command: "gh attestation verify widget-1.2.3.tar.gz -R acme/widget",
      },
    ]);
  });

  it("handles skipped-private-repo and disabled statuses clearly without commands", () => {
    const priv = buildAttestationVerification({
      repository: "acme/private-lib",
      releaseTag: "v1.0.0",
      status: "skipped-private-repo",
      artifactNames: ["private-lib.tar.gz"],
    });
    expect(priv.commands).toEqual([]);
    expect(priv.note).toMatch(/private/i);

    const dis = buildAttestationVerification({
      repository: "acme/other",
      releaseTag: "v1.0.0",
      status: "disabled",
      artifactNames: [],
    });
    expect(dis.commands).toEqual([]);
    expect(dis.note).toMatch(/disabled/i);
  });
});
