import type { AppConfig } from "../config";
import { esc, renderLayout } from "./layout";

export function renderErrorPage(params: {
  status: number;
  title: string;
  message: string;
  config: AppConfig;
}): string {
  const body = `
    <h1>${esc(params.status)} — ${esc(params.title)}</h1>
    <p class="lead">${esc(params.message)}</p>
    <p><a href="/">Return to the release catalog</a>.</p>
  `;
  return renderLayout({ title: params.title, config: params.config, body });
}
