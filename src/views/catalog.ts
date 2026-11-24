import type { AppConfig } from "../config";
import type { PackageTier, TrackedPackage } from "../kernel/types";
import { esc, renderLayout } from "./layout";

const TIER_LABELS: Record<PackageTier, string> = {
  A: "Tier A — Critical Distribution & Downstream Anchors",
  B: "Tier B — Actively Maintained Libraries & Services",
  C: "Tier C — Supporting Tooling & Internal Utilities",
};

export function renderCatalogPage(config: AppConfig): string {
  const tiers: PackageTier[] = ["A", "B", "C"];
  const sections: string[] = [];

  for (const tier of tiers) {
    const pkgs = config.catalog.filter((p) => p.tier === tier);
    if (pkgs.length === 0) continue;

    // Group by releaseStream within the tier
    const byStream = new Map<string, TrackedPackage[]>();
    for (const pkg of pkgs) {
      const list = byStream.get(pkg.releaseStream) ?? [];
      list.push(pkg);
      byStream.set(pkg.releaseStream, list);
    }

    const rows: string[] = [];
    for (const [stream, streamPkgs] of byStream.entries()) {
      for (const pkg of streamPkgs) {
        const [owner, repoName] = pkg.repo.split("/");
        const pkgHref = `/packages/${encodeURIComponent(owner ?? "")}/${encodeURIComponent(repoName ?? "")}`;
        rows.push(`
          <tr>
            <td><a href="${pkgHref}"><strong>${esc(pkg.name)}</strong></a><br><code>${esc(pkg.repo)}</code></td>
            <td><span class="badge badge-neutral">${esc(stream)}</span></td>
            <td>${esc(pkg.description || "Tracked release stream.")}</td>
            <td><a href="${pkgHref}">Releases</a></td>
          </tr>
        `);
      }
    }

    sections.push(`
      <section>
        <h2>${esc(TIER_LABELS[tier])}</h2>
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Release Stream</th>
              <th>Description</th>
              <th>Provenance</th>
            </tr>
          </thead>
          <tbody>
            ${rows.join("")}
          </tbody>
        </table>
      </section>
    `);
  }

  const emptyState =
    sections.length === 0
      ? `<div class="card"><p>No tracked packages are configured in this instance yet. Configure <code>CATALOG_JSON</code> in the instance environment to publish tracked release streams.</p></div>`
      : sections.join("\n");

  const body = `
    <h1>Release Provenance Catalog</h1>
    <p class="lead">
      Public provenance records for ${esc(config.policyOrgName)} software releases, including
      dual-format SBOMs, Sigstore build attestations, support windows, vulnerability status, and
      public contributor attributions.
    </p>
    <p>
      All releases adhere to the <a href="/policy">normative SBOM and provenance policy</a>.
    </p>
    ${emptyState}
  `;

  return renderLayout({
    title: "Release Provenance Catalog",
    config,
    body,
  });
}
