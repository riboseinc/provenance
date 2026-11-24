import type { PublicAttributionRecord, PublicPrRecord } from "./types";

const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PORTAL_INTERNAL_PATTERN = /\b(portal_id|cla_record_id|internal_id|signatory_email)\s*[:=]\s*\S+/gi;

function sanitizePublicStatement(text: string): string {
  return text
    .replace(/\x3c!--[\s\S]*?--\x3e/g, "")
    .replace(PORTAL_INTERNAL_PATTERN, "")
    .replace(EMAIL_PATTERN, "[redacted]")
    .replace(/\s+/g, " ")
    .trim();
}

function detectInstrument(body: string): string | undefined {
  const instrumentMatch = /(?:Instrument|CLA|License Instrument)\s*:\s*([^\n\r]+)/i.exec(body);
  if (instrumentMatch?.[1]) {
    return sanitizePublicStatement(instrumentMatch[1]);
  }
  if (/OCLA/i.test(body)) return "OCLA";
  if (/ICLA/i.test(body)) return "ICLA";
  if (/DCO|Signed-off-by:/i.test(body)) return "DCO";
  if (/cla\/[a-z0-9_-]+/i.test(body)) return "CLA";
  return undefined;
}

function isAttributionComment(body: string): boolean {
  return (
    /\x3c!--\s*cla-attribution\b/i.test(body) ||
    /attribution\s*:/i.test(body) ||
    /contributor license agreement/i.test(body) ||
    /cla\s*:\s*/i.test(body) ||
    /signed-off-by\s*:/i.test(body)
  );
}

/**
 * Extract public attribution records from merged PR closing/attribution comments.
 * Strictly consumes public GitHub PRs and comments; portal internals and
 * personal email addresses are never emitted.
 */
export function extractPublicAttributions(
  pullRequests: PublicPrRecord[],
): PublicAttributionRecord[] {
  const results: PublicAttributionRecord[] = [];

  for (const pr of pullRequests) {
    if (!pr.mergedAt) continue;

    // Prefer explicit attribution comments, scanning in reverse chronological order
    // so the closing/final attribution statement wins.
    const matchingComments = pr.comments
      .filter((c) => isAttributionComment(c.body))
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));

    const chosen = matchingComments[0];
    if (!chosen) continue;

    const strippedBody = chosen.body.replace(/\x3c!--[\s\S]*?--\x3e/g, "");
    const instrument = detectInstrument(strippedBody) ?? "Public Attribution";
    const statementMatch = /\b(?:Attribution|Statement)\s*:\s*([^\n\r]+)/i.exec(strippedBody);
    const rawStatement = statementMatch?.[1] ?? strippedBody;
    const attributionStatement = sanitizePublicStatement(rawStatement);

    if (!attributionStatement) continue;

    results.push({
      prNumber: pr.number,
      prTitle: pr.title,
      prUrl: pr.url,
      mergedAt: pr.mergedAt,
      authorLogin: pr.authorLogin,
      instrument,
      attributionStatement,
      commentUrl: chosen.url,
    });
  }

  return results;
}
