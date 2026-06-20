import type { ModelPricing } from "../types.js";

// ============================================================
// Model Pricing Table — Updated June 2026
// Prices in USD per 1M tokens.
// Includes `cachedInputPer1M` for providers that support prompt caching
// (Anthropic cache reads land at ~10% of standard input rate).
//
// Note: with the Opus 4.7 generation Anthropic dropped the Opus input/output
// rate from $15/$75 to $5/$25 and serves the 1M context window at standard
// pricing (no long-context premium). Earlier tables that still list Opus at
// $15/$75 over-estimate Opus cost by ~3x.
// ============================================================

export const MODEL_PRICING: Record<string, ModelPricing> = {
  // OpenAI
  "gpt-5.2": { inputPer1M: 2.50, outputPer1M: 10.0 },
  "gpt-5.1": { inputPer1M: 2.50, outputPer1M: 10.0 },
  "gpt-5": { inputPer1M: 2.50, outputPer1M: 10.0 },
  "gpt-4.1": { inputPer1M: 2.00, outputPer1M: 8.00 },
  "gpt-4o": { inputPer1M: 2.50, outputPer1M: 10.0 },
  "gpt-4o-mini": { inputPer1M: 0.15, outputPer1M: 0.60 },
  "o3": { inputPer1M: 10.0, outputPer1M: 40.0 },
  "o3-mini": { inputPer1M: 1.10, outputPer1M: 4.40 },
  "o4-mini": { inputPer1M: 1.10, outputPer1M: 4.40 },

  // Anthropic — June 2026 line-up (Fable 5, Opus 4.8/4.7/4.6, Sonnet 4.6, Haiku 4.5)
  "claude-fable-5": { inputPer1M: 10.0, outputPer1M: 50.0, cachedInputPer1M: 1.0 },
  "claude-opus-4-8": { inputPer1M: 5.0, outputPer1M: 25.0, cachedInputPer1M: 0.50 },
  "claude-opus-4-7": { inputPer1M: 5.0, outputPer1M: 25.0, cachedInputPer1M: 0.50 },
  "claude-opus-4-6": { inputPer1M: 5.0, outputPer1M: 25.0, cachedInputPer1M: 0.50 },
  "claude-sonnet-4-6": { inputPer1M: 3.0, outputPer1M: 15.0, cachedInputPer1M: 0.30 },
  "claude-sonnet-4-5": { inputPer1M: 3.0, outputPer1M: 15.0, cachedInputPer1M: 0.30 },
  "claude-haiku-4-5": { inputPer1M: 1.0, outputPer1M: 5.0, cachedInputPer1M: 0.10 },

  // Aliases
  "gpt-5.2-turbo": { inputPer1M: 2.50, outputPer1M: 10.0 },
  fable: { inputPer1M: 10.0, outputPer1M: 50.0, cachedInputPer1M: 1.0 },
  opus: { inputPer1M: 5.0, outputPer1M: 25.0, cachedInputPer1M: 0.50 },
  sonnet: { inputPer1M: 3.0, outputPer1M: 15.0, cachedInputPer1M: 0.30 },
  haiku: { inputPer1M: 1.0, outputPer1M: 5.0, cachedInputPer1M: 0.10 },
};

/** Get pricing for a model, fallback to gpt-4o-mini rates */
export function getModelPricing(model: string): ModelPricing {
  // Try exact match
  const exact = MODEL_PRICING[model];
  if (exact) return exact;

  // Try prefix match (e.g., "gpt-4o-2024-08-06" → "gpt-4o")
  for (const [key, pricing] of Object.entries(MODEL_PRICING)) {
    if (model.startsWith(key)) return pricing;
  }

  // Fallback
  return { inputPer1M: 0.15, outputPer1M: 0.60 };
}

/** Estimate cost for a given number of tokens */
export function estimateCost(
  model: string,
  inputTokens: number,
  outputTokens: number,
): number {
  const pricing = getModelPricing(model);
  return (
    (inputTokens / 1_000_000) * pricing.inputPer1M +
    (outputTokens / 1_000_000) * pricing.outputPer1M
  );
}
