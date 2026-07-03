import type {
  AIShield,
  ShieldConfig,
  ScanContext,
  ScanResult,
} from "ai-shield-core";

// ============================================================
// Shared middleware logic — used by Express and Hono adapters
// ============================================================

export interface ShieldMiddlewareConfig {
  /** AI Shield config */
  shield?: ShieldConfig;
  /** Pre-created AIShield instance (shared across routes) */
  shieldInstance?: AIShield;
  /** Extract agent ID from request */
  getAgentId?: (req: {
    headers: Record<string, string | string[] | undefined>;
    path?: string;
    url?: string;
  }) => string | undefined;
  /** Extract scan context from request */
  getContext?: (req: {
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
  }) => ScanContext;
  /** Extract text to scan from request body */
  getInput?: (body: unknown) => string | null;
  /** Custom blocked response */
  onBlocked?: (result: ScanResult) => { status: number; body: unknown };
  /** Called on warnings (non-blocking) */
  onWarning?: (result: ScanResult) => void;
  /** Skip scanning for certain paths */
  skipPaths?: string[];
}

/** Default: extract text from common chat API body shapes */
export function defaultGetInput(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;

  const obj = body as Record<string, unknown>;

  // Direct message field
  if (typeof obj.message === "string") return obj.message;
  if (typeof obj.input === "string") return obj.input;
  if (typeof obj.prompt === "string") return obj.prompt;
  if (typeof obj.text === "string") return obj.text;
  if (typeof obj.content === "string") return obj.content;
  if (typeof obj.query === "string") return obj.query;

  // OpenAI-style messages array
  if (Array.isArray(obj.messages)) {
    const userMessages = (
      obj.messages as Array<{ role?: string; content?: string }>
    )
      .filter((m) => m.role === "user" && typeof m.content === "string")
      .map((m) => m.content as string);
    if (userMessages.length > 0) return userMessages.join("\n");
  }

  return null;
}

/** Default blocked response */
export function defaultBlockedResponse(result: ScanResult): {
  status: number;
  body: unknown;
} {
  return {
    status: 403,
    body: {
      error: "Request blocked by AI Shield",
      decision: result.decision,
      violations: result.violations.map((v) => ({
        type: v.type,
        message: v.message,
      })),
    },
  };
}

/** Lazy-load AIShield instance */
let _sharedShield: AIShield | null = null;
let _shieldReady: Promise<AIShield> | null = null;

export async function getOrCreateShield(
  config: ShieldMiddlewareConfig,
): Promise<AIShield> {
  if (config.shieldInstance) return config.shieldInstance;
  if (_sharedShield) return _sharedShield;
  if (_shieldReady) return _shieldReady;

  _shieldReady = import("ai-shield-core").then((mod) => {
    _sharedShield = new mod.AIShield(config.shield ?? {});
    return _sharedShield;
  });

  return _shieldReady;
}

/** Core scan logic shared between Express and Hono */
export async function scanRequest(
  config: ShieldMiddlewareConfig,
  input: string,
  context: ScanContext,
): Promise<{
  blocked: boolean;
  result: ScanResult;
  response?: { status: number; body: unknown };
}> {
  const shield = await getOrCreateShield(config);
  const result = await shield.scan(input, context);

  if (result.decision === "block") {
    const onBlocked = config.onBlocked ?? defaultBlockedResponse;
    return { blocked: true, result, response: onBlocked(result) };
  }

  if (result.decision === "warn") {
    config.onWarning?.(result);
  }

  return { blocked: false, result };
}
