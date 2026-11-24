import type {
  ComponentHash,
  SbomComponent,
  SbomDependency,
  SbomDocument,
  SbomMetadata,
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

function uniqueStrings(values: Array<string | undefined>): string[] {
  const seen = new Set<string>();
  for (const v of values) {
    if (v && v.trim().length > 0) seen.add(v.trim());
  }
  return [...seen];
}

export function parseSpdx3(raw: unknown): SbomDocument {
  const doc = asRecord(raw);
  if (!doc || !Array.isArray(doc["@graph"])) {
    throw new Error("Invalid SPDX 3.0 document: missing @graph array.");
  }

  const graph = doc["@graph"].map(asRecord).filter((n): n is JsonRecord => Boolean(n));
  const byId = new Map<string, JsonRecord>();
  for (const node of graph) {
    const spdxId = asString(node["spdxId"]);
    const atId = asString(node["@id"]);
    if (spdxId) byId.set(spdxId, node);
    if (atId) byId.set(atId, node);
  }

  const creationInfo = graph.find((n) => n["type"] === "CreationInfo");
  const sbomNode = graph.find((n) => n["type"] === "software_Sbom");
  const annotations = graph.filter((n) => n["type"] === "Annotation");
  const packages = graph.filter((n) => n["type"] === "software_Package");
  const relationships = graph.filter((n) => n["type"] === "Relationship");

  // Author
  const createdBy = asArray(creationInfo?.["createdBy"]).map(asString).filter((s): s is string => Boolean(s));
  const authorNames = createdBy
    .map((id) => asString(byId.get(id)?.["name"]))
    .filter((s): s is string => Boolean(s));

  // Tool
  const createdUsing = asArray(creationInfo?.["createdUsing"]).map(asString).filter((s): s is string => Boolean(s));
  const toolNode = createdUsing
    .map((id) => byId.get(id))
    .find((n) => n?.["type"] === "Tool" && asString(n["name"]));
  const rawToolName = asString(toolNode?.["name"]);
  let toolName = rawToolName;
  let toolVersion: string | undefined;
  if (rawToolName) {
    const match = /^(.+?)[-@](\d+\.\d+\.\d+(?:[.-][\w]+)*)$/.exec(rawToolName);
    if (match) {
      toolName = match[1];
      toolVersion = match[2];
    }
  }

  // Annotations: sbomVersion & sbomAuthorSignature
  let sbomVersion: number | undefined;
  let signatureReference: string | undefined;
  for (const ann of annotations) {
    const stmt = asString(ann["statement"]);
    if (!stmt) continue;
    if (stmt.startsWith("sbomVersion=")) {
      const parsed = Number.parseInt(stmt.slice("sbomVersion=".length), 10);
      if (Number.isInteger(parsed) && parsed > 0) sbomVersion = parsed;
    } else if (stmt.startsWith("sbomAuthorSignature=")) {
      signatureReference = stmt.slice("sbomAuthorSignature=".length);
    }
  }

  const sbomTypes = asArray(sbomNode?.["software_sbomType"])
    .map(asString)
    .filter((s): s is string => Boolean(s));

  const metadata: SbomMetadata = {
    author: authorNames[0],
    timestamp: asString(creationInfo?.["created"]),
    toolName,
    toolVersion,
    sbomVersion,
    generationContext: sbomTypes.join(", ") || undefined,
    signatureReference,
  };

  // Licenses per package from relationships
  const licensesByPkg = new Map<string, string[]>();
  const dependencies: SbomDependency[] = [];

  for (const rel of relationships) {
    const relType = asString(rel["relationshipType"]);
    const from = asString(rel["from"]);
    const toList = asArray(rel["to"]).map(asString).filter((s): s is string => Boolean(s));
    if (!relType || !from || toList.length === 0) continue;

    if (relType === "hasDeclaredLicense" || relType === "hasConcludedLicense") {
      const existing = licensesByPkg.get(from) ?? [];
      for (const targetId of toList) {
        const targetNode = byId.get(targetId);
        const expr =
          asString(targetNode?.["simplelicensing_licenseExpression"]) ??
          asString(targetNode?.["name"]) ??
          targetId;
        existing.push(expr);
      }
      licensesByPkg.set(from, existing);
    } else if (relType === "dependsOn" || relType === "contains") {
      dependencies.push({
        from,
        to: toList,
        relationship: relType,
      });
    }
  }

  const rootElements = new Set(
    asArray(sbomNode?.["rootElement"]).map(asString).filter((s): s is string => Boolean(s)),
  );

  const components: SbomComponent[] = packages.map((pkg, idx) => {
    const id = asString(pkg["spdxId"]) ?? asString(pkg["@id"]) ?? `spdx-pkg-${idx}`;
    const supplierId = asString(pkg["suppliedBy"]);
    const supplier = supplierId ? asString(byId.get(supplierId)?.["name"]) : undefined;

    const hashes: ComponentHash[] = asArray(pkg["verifiedUsing"])
      .map(asRecord)
      .filter((h): h is JsonRecord => Boolean(h))
      .flatMap((h) => {
        const algorithm = asString(h["algorithm"]);
        const value = asString(h["hashValue"]);
        return algorithm && value ? [{ algorithm, value }] : [];
      });

    const extIds = asArray(pkg["externalIdentifier"])
      .map(asRecord)
      .filter((e): e is JsonRecord => Boolean(e));
    const cpe = extIds
      .find((e) => asString(e["externalIdentifierType"])?.toLowerCase().startsWith("cpe"))
      ?.["identifier"];

    return {
      id,
      name: asString(pkg["name"]) ?? id,
      version: asString(pkg["software_packageVersion"]) ?? "unknown",
      purl: asString(pkg["software_packageUrl"]),
      cpe: asString(cpe),
      supplier,
      hashes,
      licenses: uniqueStrings(licensesByPkg.get(id) ?? []),
      isRoot: rootElements.has(id),
    };
  });

  const allLicenses = uniqueStrings(components.flatMap((c) => c.licenses));

  return {
    format: "spdx-3.0",
    metadata,
    components,
    dependencies,
    licenses: allLicenses,
  };
}

function parseCycloneDxComponent(comp: JsonRecord, isRoot: boolean, idx: number): SbomComponent {
  const id = asString(comp["bom-ref"]) ?? asString(comp["purl"]) ?? `${asString(comp["name"]) ?? "comp"}-${idx}`;
  const supplierObj = asRecord(comp["supplier"]);
  const mfgObj = asRecord(comp["manufacturer"]);
  const supplier =
    asString(supplierObj?.["name"]) ??
    asString(mfgObj?.["name"]) ??
    asString(comp["author"]);

  const hashes: ComponentHash[] = asArray(comp["hashes"])
    .map(asRecord)
    .filter((h): h is JsonRecord => Boolean(h))
    .flatMap((h) => {
      const algorithm = asString(h["alg"]);
      const value = asString(h["content"]);
      return algorithm && value ? [{ algorithm, value }] : [];
    });

  const licenses = uniqueStrings(
    asArray(comp["licenses"])
      .map(asRecord)
      .filter((l): l is JsonRecord => Boolean(l))
      .map((l) => {
        const licObj = asRecord(l["license"]);
        return (
          asString(l["expression"]) ??
          asString(licObj?.["id"]) ??
          asString(licObj?.["name"])
        );
      }),
  );

  return {
    id,
    name: asString(comp["name"]) ?? id,
    version: asString(comp["version"]) ?? "unknown",
    purl: asString(comp["purl"]),
    cpe: asString(comp["cpe"]),
    supplier,
    hashes,
    licenses,
    isRoot,
  };
}

export function parseCycloneDx17(raw: unknown): SbomDocument {
  const doc = asRecord(raw);
  if (!doc || asString(doc["bomFormat"]) !== "CycloneDX") {
    throw new Error("Invalid CycloneDX document: bomFormat must be CycloneDX.");
  }

  const meta = asRecord(doc["metadata"]);
  const authors = asArray(meta?.["authors"])
    .map(asRecord)
    .filter((a): a is JsonRecord => Boolean(a));
  const toolsObj = asRecord(meta?.["tools"]);
  const toolComps = asArray(toolsObj?.["components"])
    .map(asRecord)
    .filter((t): t is JsonRecord => Boolean(t));
  const lifecycles = asArray(meta?.["lifecycles"])
    .map(asRecord)
    .filter((l): l is JsonRecord => Boolean(l));
  const props = asArray(meta?.["properties"])
    .map(asRecord)
    .filter((p): p is JsonRecord => Boolean(p));
  const sigObj = asRecord(doc["signature"]);

  const signatureReference =
    asString(sigObj?.["value"]) ??
    asString(props.find((p) => asString(p["name"]) === "cisa:sbom:author-signature")?.["value"]);

  const rawVersion = doc["version"];
  const sbomVersion =
    typeof rawVersion === "number" && Number.isInteger(rawVersion) && rawVersion > 0
      ? rawVersion
      : undefined;

  const metadata: SbomMetadata = {
    author: asString(authors[0]?.["name"]),
    timestamp: asString(meta?.["timestamp"]),
    toolName: asString(toolComps[0]?.["name"]),
    toolVersion: asString(toolComps[0]?.["version"]),
    sbomVersion,
    generationContext: uniqueStrings(
      lifecycles.map((l) => asString(l["phase"]) ?? asString(l["name"])),
    ).join(", ") || undefined,
    signatureReference,
  };

  const components: SbomComponent[] = [];
  const rootComp = asRecord(meta?.["component"]);
  if (rootComp) {
    components.push(parseCycloneDxComponent(rootComp, true, 0));
  }

  for (const [idx, item] of asArray(doc["components"]).entries()) {
    const rec = asRecord(item);
    if (rec) components.push(parseCycloneDxComponent(rec, false, idx + 1));
  }

  const dependencies: SbomDependency[] = asArray(doc["dependencies"])
    .map(asRecord)
    .filter((d): d is JsonRecord => Boolean(d))
    .flatMap((d) => {
      const ref = asString(d["ref"]);
      const dependsOn = asArray(d["dependsOn"]).map(asString).filter((s): s is string => Boolean(s));
      return ref && dependsOn.length > 0
        ? [{ from: ref, to: dependsOn, relationship: "dependsOn" as const }]
        : [];
    });

  const allLicenses = uniqueStrings(components.flatMap((c) => c.licenses));

  return {
    format: "cyclonedx-1.7",
    metadata,
    components,
    dependencies,
    licenses: allLicenses,
  };
}

export function parseSbom(rawJson: string | unknown): SbomDocument {
  let parsed: unknown = rawJson;
  if (typeof rawJson === "string") {
    try {
      parsed = JSON.parse(rawJson);
    } catch (err) {
      throw new Error(`Malformed SBOM JSON: ${(err as Error).message}`);
    }
  }

  const rec = asRecord(parsed);
  if (!rec) {
    throw new Error("Invalid SBOM payload: expected a JSON object.");
  }

  if (Array.isArray(rec["@graph"])) {
    return parseSpdx3(rec);
  }
  if (asString(rec["bomFormat"]) === "CycloneDX") {
    return parseCycloneDx17(rec);
  }

  throw new Error("Unsupported SBOM format: expected SPDX 3.0 (@graph) or CycloneDX 1.7 (bomFormat: CycloneDX).");
}
