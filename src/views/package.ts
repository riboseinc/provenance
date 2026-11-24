import type { AppConfig } from "../config";
import type { GitHubRelease } from "../github";
import type { TrackedPackage } from "../kernel/types";
import { esc, renderLayout } from "./layout";

export function renderPackageReleasesPage(params: {
  repo: string;
  pkg?: TrackedPackage;
  releases: GitHubRelease[];
  config: AppConfig;
}): string {
  const [owner, repoName] = params.repo.split("/");
  const title = params.pkg ? `${params.pkg.name} (${params.repo})` : params.repo;

  const rows = params.releases.map((rel) => {
    const href = `/packages/${encodeURIComponent(owner ?? "")}/${encodeURIComponent(repoName ?? "")}/releases/${encodeURIComponent(rel.tag_name)}`;
    const hasLifecycle = rel.assets.some((a) => a.name === "lifecycle.json");
    const hasSpdx = rel.assets.some((a) => a.name.endsWith(".spdx.json"));
    const hasCdx = rel.assets.some((a) => a.name.endsWith(".cdx.json"));
    const badge =
      hasLifecycle && (hasSpdx || hasCdx)
        ? `<span class="badge badge-ok">Provenance attached</span>`
        : `<span class="badge badge-neutral">Partial assets</span>`;

    return `
      <tr>
        <td><a href="${href}"><strong>${esc(rel.tag_name)}</strong></a></td>
        <td>${esc(rel.published_at ?? "—")}</td>
        <td>${badge}</td>
        <td><a href="${href}">Inspect provenance</a></td>
      </tr>
    `;
  });

  const body = `
    <p><a href="/">&larr; Back to catalog</a></p>
    <h1>${esc(title)}</h1>
    <p class="lead">${esc(params.pkg?.description || "Published GitHub releases and provenance records.")}</p>
    ${
      rows.length === 0
        ? `<div class="card"><p>No published releases were found for <code>${esc(params.repo)}</code>.</p></div>`
        : `<table>
            <thead>
              <tr>
                <th>Release Tag</th>
                <th>Published (UTC)</th>
                <th>Provenance</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>${rows.join("")}</tbody>
          </table>`
    }
  `;

  return renderLayout({ title, config: params.config, body });
}
