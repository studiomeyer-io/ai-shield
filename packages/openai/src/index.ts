// ============================================================
// @ai-shield/openai — Public API
// ============================================================

export {
  ShieldedOpenAI,
  ShieldedChatStream,
  ShieldBlockError,
  ShieldBudgetError,
  type ShieldedOpenAIConfig,
  type ChatCompletionChunk,
} from "./wrapper.js";

// Re-export core types for convenience
export type { ShieldConfig, ScanResult, ScanContext } from "ai-shield-core";

// --- Convenience factory ---

import type { ShieldedOpenAIConfig } from "./wrapper.js";
import { ShieldedOpenAI } from "./wrapper.js";

/**
 * Wrap an OpenAI client with AI Shield protection.
 *
 * @example
 * ```ts
 * import OpenAI from "openai";
 * import { createShield } from "@ai-shield/openai";
 *
 * const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
 * const shielded = createShield(openai, {
 *   agentId: "chatbot",
 *   shield: { pii: { action: "mask", locale: "de-DE" } },
 * });
 *
 * // Every call is automatically scanned
 * const response = await shielded.createChatCompletion({
 *   model: "gpt-4o",
 *   messages: [{ role: "user", content: userInput }],
 * });
 * ```
 */
export function createShield(
  client: ConstructorParameters<typeof ShieldedOpenAI>[0],
  config?: ShieldedOpenAIConfig,
): ShieldedOpenAI {
  return new ShieldedOpenAI(client, config);
}
