import type { AppConfig } from "../config";
import type { GitHubRelease } from "../github";
import type {
  AttestationVerification,
  LifecycleEvaluation,
  PublicAttributionRecord,
  SbomDocument,
  VulnerabilityReport,
} from "../kernel/types";
import { esc, renderLayout } from "./layout";

export type ReleaseViewModel = {
  repo: string;
  tag: string;
  release: GitHubRelease;
  lifecycle?: LifecycleEvaluation;
  sboms: SbomDocument[];
  noticeText?: string;
  attestation?: AttestationVerification;
  vulnerabilities: VulnerabilityReport;
  attributions: PublicAttributionRecord[];
};

function supportBadge(lifecycle?: LifecycleEvaluation): string {
  if (!lifecycle) return `<span class="badge badge-neutral">No lifecycle.json</span>`;
  if (lifecycle.status === "active") {
    return `<span class="badge badge-ok">Active (${lifecycle.daysRemaining}d remaining)</span>`;
  }
  if (lifecycle.status === "expiring") {
    return `<span class="badge badge-warn">Expiring (${lifecycle.daysRemaining}d remaining)</span>`;
  }
  return `<span class="badge badge-err">End of Life</span>`;
}

function vulnBadge(report: VulnerabilityReport): string {
  if (report.status === "clean") {
    return `<span class="badge badge-ok">Clean (0 advisories)</span>`;
  }
  return `<span class="badge badge-err">Affected (${report.advisories.length} advisories)</span>`;
}

function attestationBadge(att?: AttestationVerification): string {
  if (!att) return `<span class="badge badge-neutral">Unavailable</span>`;
  if (att.status === "attested") return `<span class="badge badge-ok">Sigstore Attested</span>`;
  if (att.status === "skipped-private-repo") {
    return `<span class="badge badge-warn">Skipped (Private Repo)</span>`;
  }
  return `<span class="badge badge-neutral">Disabled</span>`;
}

export function renderReleasePage(vm: ReleaseViewModel, config: AppConfig): string {
  const [owner, repoName] = vm.repo.split("/");
  const pkgHref = `/packages/${encodeURIComponent(owner ?? "")}/${encodeURIComponent(repoName ?? "")}`;

  const primarySbom = vm.sboms[0];
  const components = primarySbom?.components ?? [];
  const allLicenses = [...new Set(vm.sboms.flatMap((s) => s.licenses))];

  const componentRows = components.map((c) => {
    const sha = c.hashes[0] ? `${c.hashes[0].algorithm}: ${c.hashes[0].value.slice(0, 16)}…` : "—";
    return `
      <tr>
        <td><strong>${esc(c.name)}</strong>${c.isRoot ? ' <span class="badge badge-neutral">root</span>' : ""}</td>
        <td><code>${esc(c.version)}</code></td>
        <td><code>${esc(c.purl ?? "—")}</code></td>
        <td>${esc(c.supplier ?? "—")}</td>
        <td>${esc(c.licenses.join(", ") || "—")}</td>
        <td><code>${esc(sha)}</code></td>
      </tr>
    `;
  });

  const attestationSection = vm.attestation
    ? `
      <p>${attestationBadge(vm.attestation)} &mdash; ${esc(vm.attestation.note)}</p>
      ${
        vm.attestation.commands.length > 0
          ? `<pre>${esc(vm.attestation.commands.map((c) => c.command).join("\n"))}</pre>`
          : ""
      }
    `
    : `<p>No <code>lifecycle.json</code> attestation record was attached to this release.</p>`;

  const vulnRows = vm.vulnerabilities.advisories.map(
    (adv) => `
      <tr>
        <td>${adv.url ? `<a href="${esc(adv.url)}"><code>${esc(adv.id)}</code></a>` : `<code>${esc(adv.id)}</code>`}</td>
        <td><span class="badge badge-err">${esc(adv.severity)}</span></td>
        <td>${esc(adv.source)}</td>
        <td>${esc(adv.summary)}</td>
        <td>${esc(adv.affectedComponents.map((ac) => `${ac.name}@${ac.version}${ac.fixedVersion ? ` (fix: ${ac.fixedVersion})` : ""}`).join(", "))}</td>
      </tr>
    `,
  );

  const attributionRows = vm.attributions.map(
    (a) => `
      <tr>
        <td><a href="${esc(a.prUrl)}">#${esc(a.prNumber)} ${esc(a.prTitle)}</a></td>
        <td><code>@${esc(a.authorLogin)}</code></td>
        <td><span class="badge badge-neutral">${esc(a.instrument)}</span></td>
        <td>${esc(a.attributionStatement)} (<a href="${esc(a.commentUrl)}">public record</a>)</td>
      </tr>
    `,
  );

  const sbomAssetLinks = vm.release.assets
    .filter((a) => a.name.endsWith(".spdx.json") || a.name.endsWith(".cdx.json") || a.name === "lifecycle.json" || a.name === "NOTICE")
    .map((a) => `<li><a href="${esc(a.browser_download_url)}"><code>${esc(a.name)}</code></a></li>`)
    .join("");

  const body = `
    <p><a href="/">&larr; Catalog</a> &middot; <a href="${pkgHref}">${esc(vm.repo)}</a></p>
    <h1>${esc(vm.repo)} &mdash; ${esc(vm.tag)}</h1>
    <p class="lead">
      Release provenance record published from <a href="${esc(vm.release.html_url)}">GitHub Release ${esc(vm.tag)}</a>.
    </p>

    <div class="grid">
      <div class="card">
        <div class="card-label">Support Window (CRA Art. 14)</div>
        <div class="card-value">${supportBadge(vm.lifecycle)}</div>
        <div>${vm.lifecycle ? `Supported until <code>${esc(vm.lifecycle.supportUntil)}</code>` : "No lifecycle.json attached"}</div>
      </div>
      <div class="card">
        <div class="card-label">Vulnerability Status</div>
        <div class="card-value">${vulnBadge(vm.vulnerabilities)}</div>
        <div>${esc(vm.vulnerabilities.checkedComponents)} components evaluated against OSV/GHSA</div>
      </div>
      <div class="card">
        <div class="card-label">Build Attestation</div>
        <div class="card-value">${attestationBadge(vm.attestation)}</div>
        <div>SLSA Build L3 / Sigstore</div>
      </div>
      <div class="card">
        <div class="card-label">SBOM Formats</div>
        <div class="card-value">${esc(vm.sboms.map((s) => s.format).join(", ") || "None attached")}</div>
        <div>${esc(components.length)} normalized components</div>
      </div>
    </div>

    <section>
      <h2>Attestation Verification</h2>
      ${attestationSection}
    </section>

    <section>
      <h2>Vulnerability Status (OSV / GHSA)</h2>
      ${
        vulnRows.length === 0
          ? `<p>No known OSV or GHSA advisories match the ${esc(vm.vulnerabilities.checkedComponents)} components in this release.</p>`
          : `<table>
              <thead>
                <tr>
                  <th>Advisory</th>
                  <th>Severity</th>
                  <th>Source</th>
                  <th>Summary</th>
                  <th>Affected Components</th>
                </tr>
              </thead>
              <tbody>${vulnRows.join("")}</tbody>
            </table>`
      }
    </section>

    <section>
      <h2>Components (${esc(components.length)})</h2>
      ${
        componentRows.length === 0
          ? `<p>No SBOM component inventory was attached to this release.</p>`
          : `<table>
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Version</th>
                  <th>PURL</th>
                  <th>Supplier</th>
                  <th>License</th>
                  <th>Digest</th>
                </tr>
              </thead>
              <tbody>${componentRows.join("")}</tbody>
            </table>`
      }
    </section>

    <section>
      <h2>Licenses &amp; NOTICE</h2>
      <p>Observed SPDX licenses: ${allLicenses.length > 0 ? allLicenses.map((l) => `<code>${esc(l)}</code>`).join(", ") : "None declared"}.</p>
      ${vm.noticeText ? `<pre>${esc(vm.noticeText)}</pre>` : `<p>No <code>NOTICE</code> asset was attached to this release.</p>`}
    </section>

    <section>
      <h2>Public Attribution Records</h2>
      <p>Attribution statements are extracted strictly from public merged pull request comments.</p>
      ${
        attributionRows.length === 0
          ? `<p>No public attribution comments were found on recent merged pull requests.</p>`
          : `<table>
              <thead>
                <tr>
                  <th>Pull Request</th>
                  <th>Author</th>
                  <th>Instrument</th>
                  <th>Public Statement</th>
                </tr>
              </thead>
              <tbody>${attributionRows.join("")}</tbody>
            </table>`
      }
    </section>

    ${
      sbomAssetLinks
        ? `<section><h2>Attached Provenance Assets</h2><ul>${sbomAssetLinks}</ul></section>`
        : ""
    }
  `;

  return renderLayout({
    title: `${vm.repo} ${vm.tag}`,
    config,
    body,
  });
}
