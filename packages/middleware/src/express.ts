import type { ScanResult } from "ai-shield-core";
import type { ShieldMiddlewareConfig } from "./shared.js";
import { defaultGetInput, scanRequest } from "./shared.js";

// ============================================================
// Express Middleware — AI Shield route guard
// ============================================================

// Minimal Express types (avoid hard dependency on @types/express)
interface ExpressRequest {
  body?: unknown;
  path: string;
  url: string;
  method: string;
  headers: Record<string, string | string[] | undefined>;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
  locals: Record<string, unknown>;
}

type NextFunction = (err?: unknown) => void;
type ExpressMiddleware = (
  req: ExpressRequest,
  res: ExpressResponse,
  next: NextFunction,
) => void;

/**
 * Express middleware that scans request body for prompt injection and PII.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { shieldMiddleware } from "@ai-shield/middleware/express";
 *
 * const app = express();
 * app.use(express.json());
 *
 * // Protect all /api/chat routes
 * app.use("/api/chat", shieldMiddleware({
 *   shield: { injection: { strictness: "high" } },
 *   skipPaths: ["/api/chat/health"],
 * }));
 *
 * // Access scan result in route handler
 * app.post("/api/chat", (req, res) => {
 *   const shieldResult = res.locals.shieldResult as ScanResult;
 *   // shieldResult.sanitized has PII masked
 * });
 * ```
 */
export function shieldMiddleware(
  config: ShieldMiddlewareConfig = {},
): ExpressMiddleware {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    // Skip non-mutating methods
    if (
      req.method === "GET" ||
      req.method === "HEAD" ||
      req.method === "OPTIONS"
    ) {
      return next();
    }

    // Skip configured paths
    if (config.skipPaths?.some((p) => req.path.startsWith(p))) {
      return next();
    }

    const getInput = config.getInput ?? defaultGetInput;
    const input = getInput(req.body);

    // No scannable content — pass through
    if (!input) {
      return next();
    }

    const context = config.getContext?.(req) ?? {};
    if (config.getAgentId) {
      context.agentId = config.getAgentId(req);
    }

    // Async scan
    void scanRequest(config, input, context)
      .then(({ blocked, result, response }) => {
        if (blocked && response) {
          res.status(response.status).json(response.body);
          return;
        }

        // Attach result to res.locals for downstream handlers
        res.locals.shieldResult = result;
        next();
      })
      .catch((err: unknown) => {
        next(err);
      });
  };
}

export type { ShieldMiddlewareConfig, ScanResult };
