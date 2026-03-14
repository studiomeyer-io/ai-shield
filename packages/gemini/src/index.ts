// ============================================================
// ai-shield-gemini — Public API
// ============================================================

export {
  ShieldedGemini,
  ShieldedGeminiStream,
  ShieldBlockError,
  ShieldBudgetError,
  type ShieldedGeminiConfig,
  type GeminiContent,
  type GenerateContentParams,
} from "./wrapper.js";

// Re-export core types for convenience
export type {
  ShieldConfig,
  ScanResult,
  ScanContext,
} from "ai-shield-core";

// --- Convenience factory ---

import type { ShieldedGeminiConfig } from "./wrapper.js";
import { ShieldedGemini } from "./wrapper.js";

/**
 * Wrap a Gemini GenerativeModel with AI Shield protection.
 *
 * @example
 * ```ts
 * import { GoogleGenerativeAI } from "@google/generative-ai";
 * import { createShield } from "ai-shield-gemini";
 *
 * const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!);
 * const model = genAI.getGenerativeModel({ model: "gemini-pro" });
 *
 * const shielded = createShield(model, {
 *   agentId: "chatbot",
 *   shield: { pii: { action: "mask" } },
 * });
 *
 * // Every call is automatically scanned
 * const result = await shielded.generateContent("What services do you offer?");
 * ```
 */
export function createShield(
  client: ConstructorParameters<typeof ShieldedGemini>[0],
  config?: ShieldedGeminiConfig,
): ShieldedGemini {
  return new ShieldedGemini(client, config);
}
