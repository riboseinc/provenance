import type {
  AttestationStatus,
  LifecycleDocument,
  LifecycleEvaluation,
  SupportWindowStatus,
} from "./types";

const ISO_DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
const DEFAULT_EXPIRING_WINDOW_DAYS = 90;
const MS_PER_DAY = 86_400_000;

function parseUtcDate(dateStr: string): number {
  const match = ISO_DATE_PATTERN.exec(dateStr.trim());
  if (!match) {
    throw new Error(`Invalid supportUntil date "${dateStr}": expected YYYY-MM-DD.`);
  }
  const year = Number.parseInt(match[1]!, 10);
  const month = Number.parseInt(match[2]!, 10);
  const day = Number.parseInt(match[3]!, 10);
  const utc = Date.UTC(year, month - 1, day);
  const check = new Date(utc);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    throw new Error(`Invalid calendar date "${dateStr}" in lifecycle.json.`);
  }
  return utc;
}

function isAttestationStatus(v: unknown): v is AttestationStatus {
  return v === "attested" || v === "skipped-private-repo" || v === "disabled";
}

export function parseLifecycleDocument(raw: string | unknown): LifecycleDocument {
  let parsed: unknown = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`Malformed lifecycle.json: ${(err as Error).message}`);
    }
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Invalid lifecycle.json: expected a JSON object.");
  }

  const doc = parsed as Record<string, unknown>;
  if (doc["schemaVersion"] !== "1.0") {
    throw new Error(`Unsupported lifecycle.json schemaVersion "${String(doc["schemaVersion"] ?? "")}".`);
  }

  const repository = typeof doc["repository"] === "string" ? doc["repository"].trim() : "";
  const releaseTag = typeof doc["releaseTag"] === "string" ? doc["releaseTag"].trim() : "";
  const supportUntil = typeof doc["supportUntil"] === "string" ? doc["supportUntil"].trim() : "";
  const publishedAt = typeof doc["publishedAt"] === "string" ? doc["publishedAt"].trim() : "";
  const author = typeof doc["author"] === "string" ? doc["author"].trim() : "";

  if (!repository || !releaseTag || !supportUntil || !publishedAt || !author) {
    throw new Error("Invalid lifecycle.json: missing required release metadata fields.");
  }

  // Validate supportUntil calendar date
  parseUtcDate(supportUntil);

  const att = doc["attestation"];
  if (typeof att !== "object" || att === null || Array.isArray(att)) {
    throw new Error("Invalid lifecycle.json: missing attestation object.");
  }
  const attRec = att as Record<string, unknown>;
  if (typeof attRec["enabled"] !== "boolean" || !isAttestationStatus(attRec["status"])) {
    throw new Error("Invalid lifecycle.json: invalid attestation status.");
  }

  return {
    schemaVersion: "1.0",
    repository,
    releaseTag,
    supportUntil,
    publishedAt,
    author,
    attestation: {
      enabled: attRec["enabled"],
      status: attRec["status"],
    },
  };
}

export function evaluateLifecycle(
  doc: LifecycleDocument,
  options?: { nowMs?: number; expiringWindowDays?: number },
): LifecycleEvaluation {
  const nowMs = options?.nowMs ?? 0;
  const expiringWindowDays = options?.expiringWindowDays ?? DEFAULT_EXPIRING_WINDOW_DAYS;

  const nowDate = new Date(nowMs);
  const todayUtcMs = Date.UTC(
    nowDate.getUTCFullYear(),
    nowDate.getUTCMonth(),
    nowDate.getUTCDate(),
  );
  const supportUntilMs = parseUtcDate(doc.supportUntil);
  const daysRemaining = Math.floor((supportUntilMs - todayUtcMs) / MS_PER_DAY);

  let status: SupportWindowStatus;
  if (daysRemaining < 0) {
    status = "eol";
  } else if (daysRemaining <= expiringWindowDays) {
    status = "expiring";
  } else {
    status = "active";
  }

  return {
    repository: doc.repository,
    releaseTag: doc.releaseTag,
    supportUntil: doc.supportUntil,
    publishedAt: doc.publishedAt,
    author: doc.author,
    status,
    daysRemaining,
    craArticle14Compliant: status !== "eol",
    attestationStatus: doc.attestation.status,
  };
}
