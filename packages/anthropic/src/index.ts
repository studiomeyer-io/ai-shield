// ============================================================
// @ai-shield/anthropic — Public API
// ============================================================

export {
  ShieldedAnthropic,
  ShieldedAnthropicStream,
  ShieldBlockError,
  ShieldBudgetError,
  type ShieldedAnthropicConfig,
  type AnthropicMessage,
  type AnthropicCreateParams,
  type AnthropicStreamEvent,
} from "./wrapper.js";

export type { ShieldConfig, ScanResult, ScanContext } from "ai-shield-core";

// --- Convenience factory ---

import type { ShieldedAnthropicConfig } from "./wrapper.js";
import { ShieldedAnthropic } from "./wrapper.js";

/**
 * Wrap an Anthropic client with AI Shield protection.
 *
 * @example
 * ```ts
 * import Anthropic from "@anthropic-ai/sdk";
 * import { createShield } from "@ai-shield/anthropic";
 *
 * const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
 * const shielded = createShield(anthropic, {
 *   agentId: "support-bot",
 *   shield: { pii: { action: "mask" } },
 * });
 *
 * const response = await shielded.createMessage({
 *   model: "claude-sonnet-4-6",
 *   max_tokens: 1024,
 *   messages: [{ role: "user", content: userInput }],
 * });
 * ```
 */
export function createShield(
  client: ConstructorParameters<typeof ShieldedAnthropic>[0],
  config?: ShieldedAnthropicConfig,
): ShieldedAnthropic {
  return new ShieldedAnthropic(client, config);
}
