import type { AttestationStatus, AttestationVerification } from "./types";

export function buildAttestationVerification(params: {
  repository: string;
  releaseTag: string;
  status: AttestationStatus;
  artifactNames: string[];
}): AttestationVerification {
  if (params.status === "skipped-private-repo") {
    return {
      status: params.status,
      repository: params.repository,
      releaseTag: params.releaseTag,
      commands: [],
      note: "Build provenance attestation was skipped automatically because this repository is private; Sigstore public-good transparency logging is unavailable for private repositories.",
    };
  }

  if (params.status === "disabled") {
    return {
      status: params.status,
      repository: params.repository,
      releaseTag: params.releaseTag,
      commands: [],
      note: "Build provenance attestation was disabled for this release.",
    };
  }

  const targets = params.artifactNames.length > 0 ? params.artifactNames : ["<artifact>"];
  return {
    status: params.status,
    repository: params.repository,
    releaseTag: params.releaseTag,
    commands: targets.map((artifactName) => ({
      artifactName,
      command: `gh attestation verify ${artifactName} -R ${params.repository}`,
    })),
    note: "Build provenance for this release is signed with Sigstore and can be verified offline or online using the GitHub CLI.",
  };
}
