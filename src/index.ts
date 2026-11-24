import { createApp } from "./app";
import type { Env } from "./env";

/**
 * Thin entrypoint: bind the Cloudflare Worker environment into the Hono app.
 * All testable logic lives in src/app.ts and src/kernel/.
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return createApp(env).fetch(request);
  },
};
