// ============================================================
// ai-shield-ai-sdk — Public API
// AI Shield integration for the Vercel AI SDK (`ai` >= 7)
// ============================================================

export {
  aiShieldMiddleware,
  ShieldBlockError,
  type AiSdkMiddlewareConfig,
  type ShieldCallOptions,
  type ShieldPrompt,
} from "./middleware.js";

// Re-export core types for convenience
export type {
  ShieldConfig,
  ScanResult,
  ScanContext,
  OutputScanConfig,
  OutputScanResult,
} from "ai-shield-core";

// --- Convenience factory ---

import { wrapLanguageModel } from "ai";
import type { AiSdkMiddlewareConfig } from "./middleware.js";
import { aiShieldMiddleware } from "./middleware.js";

/**
 * Wrap an AI SDK language model with AI Shield protection.
 * Shorthand for `wrapLanguageModel({ model, middleware: aiShieldMiddleware(config) })`.
 *
 * @example
 * ```ts
 * import { openai } from "@ai-sdk/openai";
 * import { generateText } from "ai";
 * import { shieldModel } from "ai-shield-ai-sdk";
 *
 * const model = shieldModel(openai("gpt-4o"), {
 *   agentId: "chatbot",
 *   shield: { pii: { action: "mask", locale: "de-DE" } },
 *   outputScan: true,
 * });
 *
 * // Every call is automatically scanned
 * const { text } = await generateText({ model, prompt: userInput });
 * ```
 */
export function shieldModel(
  model: Parameters<typeof wrapLanguageModel>[0]["model"],
  config: AiSdkMiddlewareConfig = {},
): ReturnType<typeof wrapLanguageModel> {
  return wrapLanguageModel({ model, middleware: aiShieldMiddleware(config) });
}
