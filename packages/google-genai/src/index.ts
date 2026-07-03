// ============================================================
// ai-shield-google-genai — Public API
// Wrapper for the NEW unified Google Gen AI SDK (`@google/genai`).
// For the deprecated `@google/generative-ai` SDK use `ai-shield-gemini`.
// ============================================================

export {
  ShieldedGoogleGenAI,
  ShieldedGoogleGenAIStream,
  ShieldBlockError,
  ShieldBudgetError,
  type ShieldedGoogleGenAIConfig,
  type GoogleGenAIClientLike,
  type GenAIModelsLike,
  type GenAIContent,
  type GenAIPart,
  type GenAIContents,
  type GenAIGenerateContentParams,
  type GenAIGenerateContentConfig,
  type GenAIResponse,
  type GenAIShieldMeta,
} from "./wrapper.js";

// Re-export core types for convenience
export type {
  ShieldConfig,
  ScanResult,
  ScanContext,
} from "ai-shield-core";

// --- Convenience factory ---

import type {
  GoogleGenAIClientLike,
  ShieldedGoogleGenAIConfig,
} from "./wrapper.js";
import { ShieldedGoogleGenAI } from "./wrapper.js";

/**
 * Wrap a `GoogleGenAI` client (new unified Google Gen AI SDK) with
 * AI Shield protection.
 *
 * @example
 * ```ts
 * import { GoogleGenAI } from "@google/genai";
 * import { createShield } from "ai-shield-google-genai";
 *
 * const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
 *
 * const shielded = createShield(ai, {
 *   agentId: "chatbot",
 *   shield: { pii: { action: "mask" } },
 * });
 *
 * // Every call is automatically scanned
 * const response = await shielded.models.generateContent({
 *   model: "gemini-2.5-flash",
 *   contents: "What services do you offer?",
 * });
 * console.log(response.text);
 * console.log(response._shield?.input.safe);
 * ```
 */
export function createShield(
  client: GoogleGenAIClientLike,
  config?: ShieldedGoogleGenAIConfig,
): ShieldedGoogleGenAI {
  return new ShieldedGoogleGenAI(client, config);
}
