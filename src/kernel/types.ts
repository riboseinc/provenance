export type SbomFormat = "spdx-3.0" | "cyclonedx-1.7";

export type ComponentHash = {
  algorithm: string;
  value: string;
};

export type SbomComponent = {
  id: string;
  name: string;
  version: string;
  purl?: string;
  cpe?: string;
  supplier?: string;
  hashes: ComponentHash[];
  licenses: string[];
  isRoot?: boolean;
};

export type SbomDependency = {
  from: string;
  to: string[];
  relationship: "dependsOn" | "contains";
};

export type SbomMetadata = {
  author?: string;
  timestamp?: string;
  toolName?: string;
  toolVersion?: string;
  sbomVersion?: number;
  generationContext?: string;
  signatureReference?: string;
};

export type SbomDocument = {
  format: SbomFormat;
  metadata: SbomMetadata;
  components: SbomComponent[];
  dependencies: SbomDependency[];
  licenses: string[];
};

export type AttestationStatus = "attested" | "skipped-private-repo" | "disabled";

export type LifecycleDocument = {
  schemaVersion: "1.0";
  repository: string;
  releaseTag: string;
  supportUntil: string;
  publishedAt: string;
  author: string;
  attestation: {
    enabled: boolean;
    status: AttestationStatus;
  };
};

export type SupportWindowStatus = "active" | "expiring" | "eol";

export type LifecycleEvaluation = {
  repository: string;
  releaseTag: string;
  supportUntil: string;
  publishedAt: string;
  author: string;
  status: SupportWindowStatus;
  daysRemaining: number;
  craArticle14Compliant: boolean;
  attestationStatus: AttestationStatus;
};

export type VulnerabilitySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export type VulnerabilityMatch = {
  id: string;
  source: "OSV" | "GHSA";
  aliases: string[];
  summary: string;
  severity: VulnerabilitySeverity;
  url?: string;
  affectedComponents: Array<{
    name: string;
    version: string;
    purl?: string;
    fixedVersion?: string;
  }>;
};

export type VulnerabilityReport = {
  status: "clean" | "affected";
  checkedComponents: number;
  advisories: VulnerabilityMatch[];
};

export type PublicPrRecord = {
  number: number;
  title: string;
  url: string;
  mergedAt: string;
  authorLogin: string;
  comments: Array<{
    id: number | string;
    url: string;
    authorLogin: string;
    body: string;
    createdAt: string;
  }>;
};

export type PublicAttributionRecord = {
  prNumber: number;
  prTitle: string;
  prUrl: string;
  mergedAt: string;
  authorLogin: string;
  instrument: string;
  attributionStatement: string;
  commentUrl: string;
};

export type AttestationVerification = {
  status: AttestationStatus;
  repository: string;
  releaseTag: string;
  commands: Array<{
    artifactName: string;
    command: string;
  }>;
  note: string;
};

export type PackageTier = "A" | "B" | "C";

export type TrackedPackage = {
  repo: string;
  name: string;
  tier: PackageTier;
  releaseStream: string;
  description: string;
  osvFeedUrl?: string;
  ghsaFeedUrl?: string;
};
