import type { ScanResult } from "ai-shield-core";
import type { ShieldMiddlewareConfig } from "./shared.js";
import { defaultGetInput, scanRequest } from "./shared.js";

// ============================================================
// Hono Middleware — AI Shield route guard
// ============================================================

// Minimal Hono types (avoid hard dependency)
interface HonoContext {
  req: {
    method: string;
    path: string;
    url: string;
    header(name: string): string | undefined;
    json(): Promise<unknown>;
    raw: { headers: Headers };
  };
  json(data: unknown, status?: number): Response;
  set(key: string, value: unknown): void;
  get(key: string): unknown;
}

type HonoNext = () => Promise<void>;
type HonoMiddleware = (
  c: HonoContext,
  next: HonoNext,
) => Promise<Response | void>;

/**
 * Hono middleware that scans request body for prompt injection and PII.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { shieldMiddleware } from "@ai-shield/middleware/hono";
 *
 * const app = new Hono();
 *
 * // Protect chat routes
 * app.use("/api/chat/*", shieldMiddleware({
 *   shield: { injection: { strictness: "high" } },
 * }));
 *
 * app.post("/api/chat", async (c) => {
 *   const shieldResult = c.get("shieldResult") as ScanResult;
 *   // Use shieldResult.sanitized for PII-masked input
 * });
 * ```
 */
export function shieldMiddleware(
  config: ShieldMiddlewareConfig = {},
): HonoMiddleware {
  return async (c: HonoContext, next: HonoNext): Promise<Response | void> => {
    // Skip non-mutating methods
    if (
      c.req.method === "GET" ||
      c.req.method === "HEAD" ||
      c.req.method === "OPTIONS"
    ) {
      return next();
    }

    // Skip configured paths
    if (config.skipPaths?.some((p) => c.req.path.startsWith(p))) {
      return next();
    }

    // Parse body
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      // No JSON body — pass through
      return next();
    }

    const getInput = config.getInput ?? defaultGetInput;
    const input = getInput(body);

    if (!input) {
      return next();
    }

    // Build context from headers
    const headers: Record<string, string | string[] | undefined> = {};
    c.req.raw.headers.forEach((value, key) => {
      headers[key] = value;
    });

    const context = config.getContext?.({ headers, body }) ?? {};
    if (config.getAgentId) {
      context.agentId = config.getAgentId({
        headers,
        path: c.req.path,
        url: c.req.url,
      });
    }

    const { blocked, result, response } = await scanRequest(
      config,
      input,
      context,
    );

    if (blocked && response) {
      return c.json(response.body, response.status);
    }

    // Attach result for downstream handlers
    c.set("shieldResult", result);
    return next();
  };
}

export type { ShieldMiddlewareConfig, ScanResult };
