# provenance

The Ribose provenance surface: per-release public pages answering what
is in each artifact (SBOM), how it was built (signed attestation), who
contributed it under which instrument (the public attribution record),
what license governs it, and its vulnerability and support status.

The strategy: Ribose publishes provenance-complete releases. Every
artifact a consumer receives — Thunderbird bundling RNP, an agency
running metanorma — carries the machine-readable answer to an
auditor's questions, and this site is where the chain starts.

- **The app**: a Cloudflare Worker (the estate pattern — pure kernel,
  thin service, D1/KV ephemeral only). It reads public GitHub Releases,
  the attached SBOMs and attestations, OSV/GHSA feeds, and links the
  merged pull requests' public attribution statements. No personal
  data leaves the enforcement system: the panel links public records,
  it never re-publishes portal internals.
- **The policy**: the estate SBOM policy (formats, the CISA 2026
  Minimum Elements mapping, supplier identity, PURL conventions, the
  support-period declaration) renders here as the normative document.
- **The instance**: deployment configuration lives in the private
  `ribosei/provenance-instance` (the `cla-instance` pattern — public
  app, private instance; instance data is vars, secrets, and rows,
  never compiled in).
- **The workflow**: releases gain their provenance through the
  reusable workflow at `riboseinc/provenance-release`, pinned by
  commit SHA by every consuming repository.

## Status

Greenfield (2026-11-19). The master task lives in the issue tracker.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
