import type { AppConfig } from "../config";
import { buildPolicySummary } from "../policy/sbom-policy";
import { esc, renderLayout } from "./layout";

export function renderPolicyPage(config: AppConfig): string {
  const policy = buildPolicySummary(config);

  const cisaRows = policy.cisaMapping
    .map(
      (row) => `
      <tr>
        <td><strong>${esc(row.element)}</strong></td>
        <td><code>${esc(row.spdx3Field)}</code></td>
        <td><code>${esc(row.cycloneDx17Field)}</code></td>
        <td>${esc(row.requirement)}</td>
      </tr>
    `,
    )
    .join("");

  const tierRows = policy.tiers
    .map(
      (t) => `
      <tr>
        <td><strong>Tier ${esc(t.tier)}</strong></td>
        <td>${esc(t.title)}</td>
        <td>${esc(t.requirements)}</td>
      </tr>
    `,
    )
    .join("");

  const body = `
    <p><a href="/">&larr; Back to catalog</a></p>
    <h1>Normative Estate SBOM &amp; Provenance Policy</h1>
    <p class="lead">
      This document defines the binding software bill of materials (SBOM), build attestation,
      supplier identity, and support-period requirements for software published by
      ${esc(policy.orgName)}.
    </p>

    <section>
      <h2>1. Dual-Format SBOM Requirement</h2>
      <p>
        Every tracked release must publish one unified dependency graph serialized in both
        <strong>SPDX 3.0</strong> (<code>*.spdx.json</code>) and
        <strong>CycloneDX 1.7</strong> (<code>*.cdx.json</code>).
        Both documents must pass automated CISA 2026 Minimum Elements validation before release
        assets are attached; any validation failure blocks the release.
      </p>
    </section>

    <section>
      <h2>2. CISA 2026 Minimum Elements Mapping</h2>
      <p>
        Every emitted SPDX 3.0 and CycloneDX 1.7 document must satisfy all 17 CISA 2026
        Minimum Elements listed below.
      </p>
      <table>
        <thead>
          <tr>
            <th>Element</th>
            <th>SPDX 3.0 Field</th>
            <th>CycloneDX 1.7 Field</th>
            <th>Normative Requirement</th>
          </tr>
        </thead>
        <tbody>${cisaRows}</tbody>
      </table>
    </section>

    <section>
      <h2>3. Supplier Identity &amp; PURL Conventions</h2>
      <p>
        The canonical supplier identity for first-party artifacts published by this instance is
        <strong>${esc(policy.supplierName)}</strong>.
        All components must carry a valid Package URL (PURL) following the
        <code>pkg:&lt;type&gt;/&lt;namespace&gt;/&lt;name&gt;@&lt;version&gt;</code> specification,
        using the organization namespace <code>${esc(policy.purlNamespace)}</code> where applicable.
      </p>
    </section>

    <section>
      <h2>4. Package Tiers</h2>
      <table>
        <thead>
          <tr>
            <th>Tier</th>
            <th>Classification</th>
            <th>Release Requirements</th>
          </tr>
        </thead>
        <tbody>${tierRows}</tbody>
      </table>
    </section>

    <section>
      <h2>5. Support-Period Declarations (CRA Article 14)</h2>
      <p>
        Every release must declare an explicit end-of-support date in ISO 8601
        (<code>YYYY-MM-DD</code>) format via the attached <code>lifecycle.json</code> asset
        and the release notes support-period stamp. Releases are classified as
        <strong>Active</strong> (more than 90 days remaining), <strong>Expiring</strong>
        (90 days or fewer remaining), or <strong>End of Life</strong> (past the declared
        <code>supportUntil</code> date).
      </p>
      ${
        policy.supportContactUrl
          ? `<p>Vulnerability reports and support inquiries are handled via <a href="${esc(policy.supportContactUrl)}">${esc(policy.supportContactUrl)}</a>.</p>`
          : ""
      }
    </section>
  `;

  return renderLayout({
    title: "Normative SBOM Policy",
    config,
    body,
  });
}
