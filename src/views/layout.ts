import type { AppConfig } from "../config";

export function esc(value: string | number | undefined | null): string {
  const s = value === undefined || value === null ? "" : String(value);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const CSS = `
:root {
  --bg: #ffffff;
  --fg: #111827;
  --muted: #4b5563;
  --border: #e5e7eb;
  --surface: #f9fafb;
  --accent: #1d4ed8;
  --ok-bg: #ecfdf5;
  --ok-fg: #065f46;
  --warn-bg: #fffbeb;
  --warn-fg: #92400e;
  --err-bg: #fef2f2;
  --err-fg: #991b1b;
  --neutral-bg: #f3f4f6;
  --neutral-fg: #374151;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.6;
  color: var(--fg);
  background: var(--bg);
}
header {
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}
.nav-inner, main, footer {
  max-width: 1080px;
  margin: 0 auto;
  padding: 0 1.25rem;
}
.nav-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 0.9rem;
  padding-bottom: 0.9rem;
  gap: 1rem;
  flex-wrap: wrap;
}
.brand {
  font-weight: 700;
  font-size: 1.05rem;
  color: var(--fg);
  text-decoration: none;
}
nav a {
  color: var(--muted);
  text-decoration: none;
  margin-left: 1.25rem;
  font-size: 0.95rem;
}
nav a:hover { color: var(--accent); text-decoration: underline; }
main { padding-top: 2rem; padding-bottom: 3rem; }
footer {
  border-top: 1px solid var(--border);
  padding-top: 1.25rem;
  padding-bottom: 2rem;
  color: var(--muted);
  font-size: 0.875rem;
}
h1, h2, h3 { line-height: 1.25; margin-top: 1.75rem; margin-bottom: 0.6rem; }
h1 { margin-top: 0; font-size: 1.75rem; }
h2 { font-size: 1.25rem; border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; }
.lead { color: var(--muted); font-size: 1.02rem; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1rem;
  margin: 1.25rem 0;
}
.card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  background: var(--bg);
}
.card-label {
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  margin-bottom: 0.25rem;
}
.card-value { font-size: 1.05rem; font-weight: 600; }
.badge {
  display: inline-block;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  font-size: 0.8rem;
  font-weight: 600;
}
.badge-ok { background: var(--ok-bg); color: var(--ok-fg); }
.badge-warn { background: var(--warn-bg); color: var(--warn-fg); }
.badge-err { background: var(--err-bg); color: var(--err-fg); }
.badge-neutral { background: var(--neutral-bg); color: var(--neutral-fg); }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 1rem 0;
  font-size: 0.9rem;
}
th, td {
  text-align: left;
  padding: 0.6rem 0.7rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th { background: var(--surface); font-weight: 600; }
code, pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.86rem;
}
pre {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.85rem 1rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
}
a { color: var(--accent); }
`;

export function renderLayout(params: {
  title: string;
  config: AppConfig;
  body: string;
}): string {
  const supportLink = params.config.supportContactUrl
    ? ` &middot; <a href="${esc(params.config.supportContactUrl)}">Security &amp; Support</a>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(params.title)} — ${esc(params.config.instanceName)}</title>
  <style>${CSS}</style>
</head>
<body>
  <header>
    <div class="nav-inner">
      <a class="brand" href="/">${esc(params.config.instanceName)}</a>
      <nav aria-label="Primary">
        <a href="/">Catalog</a>
        <a href="/policy">SBOM Policy</a>
      </nav>
    </div>
  </header>
  <main>
    ${params.body}
  </main>
  <footer>
    <div>${esc(params.config.policyOrgName)} &middot; ${esc(params.config.instanceHost)}${supportLink}</div>
  </footer>
</body>
</html>`;
}
