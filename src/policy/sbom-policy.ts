import type { AppConfig } from "../config";

export type CisaMappingRow = {
  element: string;
  spdx3Field: string;
  cycloneDx17Field: string;
  requirement: string;
};

export const CISA_2026_MAPPING: CisaMappingRow[] = [
  {
    element: "SBOM Author",
    spdx3Field: "CreationInfo.createdBy -> Organization/Person.name",
    cycloneDx17Field: "metadata.authors[].name",
    requirement: "Identifies the entity that generated and takes responsibility for the SBOM.",
  },
  {
    element: "SBOM Author Signature",
    spdx3Field: "Annotation.statement (sbomAuthorSignature=...)",
    cycloneDx17Field: "signature or metadata.properties[cisa:sbom:author-signature]",
    requirement: "Binds the SBOM payload to an author signature or Sigstore attestation reference.",
  },
  {
    element: "SBOM Data Format Name",
    spdx3Field: "@context (SPDX 3.0 context)",
    cycloneDx17Field: 'bomFormat ("CycloneDX")',
    requirement: "Declares the machine-readable SBOM specification family.",
  },
  {
    element: "SBOM Data Format Version",
    spdx3Field: 'CreationInfo.specVersion ("3.0.x")',
    cycloneDx17Field: 'specVersion ("1.7")',
    requirement: "Declares the exact specification version used to serialize the document.",
  },
  {
    element: "SBOM Generation Context",
    spdx3Field: "software_Sbom.software_sbomType",
    cycloneDx17Field: "metadata.lifecycles[].phase",
    requirement: "Records the lifecycle phase in which the SBOM was produced (for example, build).",
  },
  {
    element: "SBOM Timestamp",
    spdx3Field: "CreationInfo.created (RFC 9557)",
    cycloneDx17Field: "metadata.timestamp (RFC 9557)",
    requirement: "Records the UTC timestamp of SBOM generation with explicit timezone offset.",
  },
  {
    element: "SBOM Tool Name",
    spdx3Field: "CreationInfo.createdUsing -> Tool.name",
    cycloneDx17Field: "metadata.tools.components[].name",
    requirement: "Identifies the software tool that emitted the dependency graph.",
  },
  {
    element: "SBOM Tool Version",
    spdx3Field: "CreationInfo.createdUsing -> Tool.name (<tool>-<version>)",
    cycloneDx17Field: "metadata.tools.components[].version",
    requirement: "Records the exact semantic version of the SBOM emitter.",
  },
  {
    element: "SBOM Version",
    spdx3Field: "Annotation.statement (sbomVersion=<n>)",
    cycloneDx17Field: "version (positive integer)",
    requirement: "Tracks monotonic revisions of the SBOM for a given release.",
  },
  {
    element: "Component Producer",
    spdx3Field: "software_Package.suppliedBy -> Agent.name",
    cycloneDx17Field: "components[].supplier.name",
    requirement: "Identifies the upstream supplier or manufacturer of each component.",
  },
  {
    element: "Component Name",
    spdx3Field: "software_Package.name",
    cycloneDx17Field: "components[].name",
    requirement: "States the canonical component name.",
  },
  {
    element: "Component Version",
    spdx3Field: "software_Package.software_packageVersion",
    cycloneDx17Field: "components[].version",
    requirement: "States the exact component version resolved during the build.",
  },
  {
    element: "Component Identifiers",
    spdx3Field: "software_Package.software_packageUrl / externalIdentifier",
    cycloneDx17Field: "components[].purl / components[].cpe",
    requirement: "Provides globally unique Package URLs (PURL) or CPE identifiers for vulnerability matching.",
  },
  {
    element: "Component Hash Value",
    spdx3Field: "software_Package.verifiedUsing[].hashValue",
    cycloneDx17Field: "components[].hashes[].content",
    requirement: "Provides cryptographic digest values verifying artifact integrity.",
  },
  {
    element: "Component Hash Algorithm",
    spdx3Field: "software_Package.verifiedUsing[].algorithm",
    cycloneDx17Field: "components[].hashes[].alg",
    requirement: "Declares the digest algorithm (SHA-256 or stronger) paired with each hash value.",
  },
  {
    element: "Component License",
    spdx3Field: "Relationship (hasDeclaredLicense / hasConcludedLicense)",
    cycloneDx17Field: "components[].licenses[].expression / license.id",
    requirement: "Records SPDX license expressions or identifiers for every shipped component.",
  },
  {
    element: "Component Dependency Relationship",
    spdx3Field: "Relationship (dependsOn / contains)",
    cycloneDx17Field: "dependencies[].ref -> dependsOn[]",
    requirement: "Captures directed dependency edges from the root artifact through transitive packages.",
  },
];

export type TierDefinition = {
  tier: "A" | "B" | "C";
  title: string;
  requirements: string;
};

export const TIER_DEFINITIONS: TierDefinition[] = [
  {
    tier: "A",
    title: "Tier A — Critical Distribution & Downstream Anchors",
    requirements:
      "Every release must attach dual-format SBOMs (SPDX 3.0 and CycloneDX 1.7) validated against all 17 CISA 2026 Minimum Elements, a SLSA Build Level 3 Sigstore attestation, a generated NOTICE file, a lifecycle.json support-period record, and a repository SUPPORT.md.",
  },
  {
    tier: "B",
    title: "Tier B — Actively Maintained Libraries & Services",
    requirements:
      "Every release must attach dual-format SBOMs, a generated NOTICE file, and a lifecycle.json support-period record; SLSA Build Level 3 attestation is required for all public repositories.",
  },
  {
    tier: "C",
    title: "Tier C — Supporting Tooling & Internal Utilities",
    requirements:
      "Releases must declare a support status in lifecycle.json and attach at least one CISA-validated SBOM format alongside license attribution.",
  },
];

export function buildPolicySummary(config: AppConfig) {
  return {
    orgName: config.policyOrgName,
    supplierName: config.policySupplierName,
    purlNamespace: config.policyPurlNamespace,
    supportContactUrl: config.supportContactUrl,
    cisaMapping: CISA_2026_MAPPING,
    tiers: TIER_DEFINITIONS,
  };
}
