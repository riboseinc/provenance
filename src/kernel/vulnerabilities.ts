import type {
  SbomComponent,
  VulnerabilityMatch,
  VulnerabilityReport,
  VulnerabilitySeverity,
} from "./types";

type JsonRecord = Record<string, unknown>;

function asRecord(v: unknown): JsonRecord | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as JsonRecord)
    : undefined;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/**
 * Strip version, qualifiers, and subpath from a PURL to obtain the package identity:
 * e.g. pkg:cargo/rnp@0.17.1?arch=x86_64 -> pkg:cargo/rnp
 */
export function normalizeBasePurl(purl: string): string {
  const noSubpath = purl.split("#")[0] ?? purl;
  const noQualifiers = noSubpath.split("?")[0] ?? noSubpath;
  const atIdx = noQualifiers.lastIndexOf("@");
  const slashIdx = noQualifiers.lastIndexOf("/");
  if (atIdx > slashIdx && atIdx !== -1) {
    return noQualifiers.slice(0, atIdx).toLowerCase();
  }
  return noQualifiers.toLowerCase();
}

export function extractPurlVersion(purl: string): string | undefined {
  const noSubpath = purl.split("#")[0] ?? purl;
  const noQualifiers = noSubpath.split("?")[0] ?? noSubpath;
  const atIdx = noQualifiers.lastIndexOf("@");
  const slashIdx = noQualifiers.lastIndexOf("/");
  if (atIdx > slashIdx && atIdx !== -1) {
    return decodeURIComponent(noQualifiers.slice(atIdx + 1));
  }
  return undefined;
}

/**
 * Compare two dot-separated version strings (with optional pre-release/v-prefix).
 * Returns -1 if a < b, 0 if a == b, 1 if a > b.
 */
export function compareVersions(a: string, b: string): number {
  const clean = (v: string): string => v.trim().replace(/^v/i, "").split("+")[0] ?? v;
  const [aCore, aPre] = clean(a).split("-", 2);
  const [bCore, bPre] = clean(b).split("-", 2);

  const aParts = (aCore ?? "").split(".").map((p) => Number.parseInt(p, 10));
  const bParts = (bCore ?? "").split(".").map((p) => Number.parseInt(p, 10));
  const len = Math.max(aParts.length, bParts.length);

  for (let i = 0; i < len; i++) {
    const av = aParts[i];
    const bv = bParts[i];
    const aNum = av !== undefined && Number.isFinite(av) ? av : 0;
    const bNum = bv !== undefined && Number.isFinite(bv) ? bv : 0;
    if (aNum < bNum) return -1;
    if (aNum > bNum) return 1;
  }

  if (aPre && !bPre) return -1;
  if (!aPre && bPre) return 1;
  if (aPre && bPre) {
    return aPre < bPre ? -1 : aPre > bPre ? 1 : 0;
  }
  return 0;
}

function isVersionInOsvRange(
  version: string,
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>,
): { matched: boolean; fixedVersion?: string } {
  let active = false;
  let fixedVersion: string | undefined;

  for (const ev of events) {
    if (ev.introduced !== undefined) {
      if (ev.introduced === "0" || compareVersions(version, ev.introduced) >= 0) {
        active = true;
      }
    }
    if (ev.fixed !== undefined) {
      if (compareVersions(version, ev.fixed) < 0) {
        fixedVersion = ev.fixed;
      } else {
        active = false;
      }
    }
    if (ev.last_affected !== undefined) {
      if (compareVersions(version, ev.last_affected) > 0) {
        active = false;
      }
    }
  }

  return { matched: active, fixedVersion };
}

function isVersionInGhsaRange(version: string, rangeExpr: string): boolean {
  const clauses = rangeExpr
    .split(",")
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
  if (clauses.length === 0) return false;

  for (const clause of clauses) {
    const match = /^(<=|>=|<|>|=)\s*(.+)$/.exec(clause);
    if (!match) {
      if (compareVersions(version, clause) !== 0) return false;
      continue;
    }
    const op = match[1]!;
    const target = match[2]!.trim();
    const cmp = compareVersions(version, target);
    if (op === "<" && !(cmp < 0)) return false;
    if (op === "<=" && !(cmp <= 0)) return false;
    if (op === ">" && !(cmp > 0)) return false;
    if (op === ">=" && !(cmp >= 0)) return false;
    if (op === "=" && cmp !== 0) return false;
  }
  return true;
}

function normalizeSeverity(raw: unknown): VulnerabilitySeverity {
  if (typeof raw === "string") {
    const upper = raw.trim().toUpperCase();
    if (upper === "CRITICAL" || upper === "HIGH" || upper === "MEDIUM" || upper === "LOW") {
      return upper;
    }
    if (upper === "MODERATE") return "MEDIUM";
  }
  return "UNKNOWN";
}

function severityFromOsv(advisory: JsonRecord): VulnerabilitySeverity {
  const dbSpecific = asRecord(advisory["database_specific"]);
  const dbSev = normalizeSeverity(dbSpecific?.["severity"]);
  if (dbSev !== "UNKNOWN") return dbSev;

  for (const sev of asArray(advisory["severity"]).map(asRecord)) {
    if (!sev) continue;
    const score = asString(sev["score"]);
    if (!score) continue;
    // If numeric CVSS score is provided directly
    const num = Number.parseFloat(score);
    if (Number.isFinite(num)) {
      if (num >= 9.0) return "CRITICAL";
      if (num >= 7.0) return "HIGH";
      if (num >= 4.0) return "MEDIUM";
      return "LOW";
    }
  }
  return "UNKNOWN";
}

function matchesGhsaPackage(
  component: SbomComponent,
  ecosystem: string | undefined,
  pkgName: string | undefined,
): boolean {
  if (!pkgName) return false;
  const targetName = pkgName.toLowerCase();
  if (component.purl) {
    const base = normalizeBasePurl(component.purl);
    const eco = ecosystem?.toLowerCase();
    const purlBody = base.replace(/^pkg:/, "");
    const [purlType, ...rest] = purlBody.split("/");
    const purlName = rest.join("/");
    if (purlName === targetName || purlName.endsWith(`/${targetName}`)) {
      if (!eco) return true;
      if (eco === purlType) return true;
      if (eco === "rubygems" && purlType === "gem") return true;
      if (eco === "crates.io" && purlType === "cargo") return true;
      if (eco === "pip" && purlType === "pypi") return true;
      if (eco === "go" && purlType === "golang") return true;
    }
  }
  return component.name.toLowerCase() === targetName;
}

export function matchVulnerabilities(params: {
  components: SbomComponent[];
  osvAdvisories?: unknown[];
  ghsaAdvisories?: unknown[];
}): VulnerabilityReport {
  const matchesByKey = new Map<string, VulnerabilityMatch>();

  // 1. OSV matching
  for (const rawAdv of params.osvAdvisories ?? []) {
    const adv = asRecord(rawAdv);
    if (!adv) continue;
    const id = asString(adv["id"]);
    if (!id) continue;

    const aliases = asArray(adv["aliases"]).map(asString).filter((s): s is string => Boolean(s));
    const summary = asString(adv["summary"]) ?? asString(adv["details"]) ?? id;
    const severity = severityFromOsv(adv);
    const refs = asArray(adv["references"]).map(asRecord).filter((r): r is JsonRecord => Boolean(r));
    const url = asString(refs.find((r) => asString(r["type"]) === "ADVISORY")?.["url"]) ?? asString(refs[0]?.["url"]);

    const affectedList = asArray(adv["affected"]).map(asRecord).filter((a): a is JsonRecord => Boolean(a));
    for (const comp of params.components) {
      const compVersion = comp.version !== "unknown"
        ? comp.version
        : (comp.purl ? extractPurlVersion(comp.purl) : undefined);
      if (!compVersion) continue;

      const compBasePurl = comp.purl ? normalizeBasePurl(comp.purl) : undefined;

      for (const aff of affectedList) {
        const pkg = asRecord(aff["package"]);
        const affPurl = asString(pkg?.["purl"]);
        const affName = asString(pkg?.["name"]);
        const affEco = asString(pkg?.["ecosystem"]);

        const purlMatch = Boolean(compBasePurl && affPurl && normalizeBasePurl(affPurl) === compBasePurl);
        const nameMatch = !affPurl && matchesGhsaPackage(comp, affEco, affName);
        if (!purlMatch && !nameMatch) continue;

        const exactVersions = asArray(aff["versions"]).map(asString).filter((s): s is string => Boolean(s));
        let isAffected = exactVersions.includes(compVersion);
        let fixedVersion: string | undefined;

        for (const range of asArray(aff["ranges"]).map(asRecord)) {
          if (!range) continue;
          const events = asArray(range["events"])
            .map(asRecord)
            .filter((e): e is JsonRecord => Boolean(e))
            .map((e) => ({
              introduced: asString(e["introduced"]),
              fixed: asString(e["fixed"]),
              last_affected: asString(e["last_affected"]),
            }));
          const res = isVersionInOsvRange(compVersion, events);
          if (res.matched) {
            isAffected = true;
            if (res.fixedVersion) fixedVersion = res.fixedVersion;
          }
        }

        if (isAffected) {
          const key = `OSV:${id}`;
          const existing = matchesByKey.get(key) ?? {
            id,
            source: "OSV" as const,
            aliases,
            summary,
            severity,
            url,
            affectedComponents: [],
          };
          existing.affectedComponents.push({
            name: comp.name,
            version: compVersion,
            purl: comp.purl,
            fixedVersion,
          });
          matchesByKey.set(key, existing);
        }
      }
    }
  }

  // 2. GHSA matching
  for (const rawAdv of params.ghsaAdvisories ?? []) {
    const adv = asRecord(rawAdv);
    if (!adv) continue;
    const ghsaId = asString(adv["ghsa_id"]) ?? asString(adv["id"]);
    if (!ghsaId) continue;

    const cveId = asString(adv["cve_id"]);
    const aliases = cveId ? [cveId] : [];
    const summary = asString(adv["summary"]) ?? ghsaId;
    const severity = normalizeSeverity(adv["severity"]);
    const url = asString(adv["html_url"]);

    const vulns = asArray(adv["vulnerabilities"]).map(asRecord).filter((v): v is JsonRecord => Boolean(v));
    for (const comp of params.components) {
      const compVersion = comp.version !== "unknown"
        ? comp.version
        : (comp.purl ? extractPurlVersion(comp.purl) : undefined);
      if (!compVersion) continue;

      for (const vuln of vulns) {
        const pkg = asRecord(vuln["package"]);
        const eco = asString(pkg?.["ecosystem"]);
        const name = asString(pkg?.["name"]);
        if (!matchesGhsaPackage(comp, eco, name)) continue;

        const rangeExpr = asString(vuln["vulnerable_version_range"]);
        if (!rangeExpr || !isVersionInGhsaRange(compVersion, rangeExpr)) continue;

        const patched = asRecord(vuln["first_patched_version"]);
        const fixedVersion = asString(patched?.["identifier"]) ?? asString(vuln["first_patched_version"]);

        const key = `GHSA:${ghsaId}`;
        const existing = matchesByKey.get(key) ?? {
          id: ghsaId,
          source: "GHSA" as const,
          aliases,
          summary,
          severity,
          url,
          affectedComponents: [],
        };
        existing.affectedComponents.push({
          name: comp.name,
          version: compVersion,
          purl: comp.purl,
          fixedVersion,
        });
        matchesByKey.set(key, existing);
      }
    }
  }

  const advisories = [...matchesByKey.values()];
  return {
    status: advisories.length === 0 ? "clean" : "affected",
    checkedComponents: params.components.length,
    advisories,
  };
}
