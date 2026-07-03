import { describe, it, expect } from "vitest";
import { CostTracker } from "../../packages/core/src/cost/tracker.js";
import {
  getModelPricing,
  estimateCost,
  MODEL_PRICING,
} from "../../packages/core/src/cost/pricing.js";
import { detectAnomaly } from "../../packages/core/src/cost/anomaly.js";

describe("CostTracker", () => {
  describe("budget checks", () => {
    it("allows when no budget configured", async () => {
      const tracker = new CostTracker({});
      const result = await tracker.checkBudget("unknown", "gpt-4o", 1000);
      expect(result.allowed).toBe(true);
      expect(result.remainingBudget).toBe(Infinity);
    });

    it("allows when under budget", async () => {
      const tracker = new CostTracker({
        agent: { softLimit: 5, hardLimit: 10, period: "daily" },
      });
      const result = await tracker.checkBudget(
        "agent",
        "gpt-4o-mini",
        1000,
        500,
      );
      expect(result.allowed).toBe(true);
      expect(result.remainingBudget).toBeGreaterThan(0);
    });

    it("blocks when over hard limit", async () => {
      const tracker = new CostTracker({
        agent: { softLimit: 0.0001, hardLimit: 0.0001, period: "daily" },
      });

      // Record a cost first
      await tracker.recordCost("agent", "claude-opus-4-6", 10000, 5000);

      const result = await tracker.checkBudget(
        "agent",
        "claude-opus-4-6",
        10000,
        5000,
      );
      expect(result.allowed).toBe(false);
      expect(result.warning).toBeDefined();
    });

    it("warns when approaching soft limit", async () => {
      const tracker = new CostTracker({
        agent: { softLimit: 0.001, hardLimit: 10, period: "daily" },
      });

      // Record enough to exceed soft limit
      await tracker.recordCost("agent", "gpt-4o", 5000, 2000);

      const result = await tracker.checkBudget("agent", "gpt-4o", 5000, 2000);
      expect(result.allowed).toBe(true);
      expect(result.warning).toBeDefined();
    });
  });

  describe("cost recording", () => {
    it("records cost and returns record", async () => {
      const tracker = new CostTracker({
        agent: { softLimit: 100, hardLimit: 200, period: "daily" },
      });
      const record = await tracker.recordCost("agent", "gpt-4o", 1000, 500);
      expect(record.entityId).toBe("agent");
      expect(record.model).toBe("gpt-4o");
      expect(record.inputTokens).toBe(1000);
      expect(record.outputTokens).toBe(500);
      expect(record.cost).toBeGreaterThan(0);
      expect(record.timestamp).toBeInstanceOf(Date);
    });

    it("accumulates costs across multiple calls", async () => {
      const tracker = new CostTracker({
        agent: { softLimit: 100, hardLimit: 200, period: "daily" },
      });

      await tracker.recordCost("agent", "gpt-4o", 1000, 500);
      await tracker.recordCost("agent", "gpt-4o", 2000, 1000);

      const spend = await tracker.getCurrentSpend("agent");
      expect(spend).toBeGreaterThan(0);
    });

    it("tracks global budget separately", async () => {
      const tracker = new CostTracker({
        agent: { softLimit: 100, hardLimit: 200, period: "daily" },
        global: { softLimit: 500, hardLimit: 1000, period: "daily" },
      });

      await tracker.recordCost("agent", "gpt-4o", 1000, 500);
      const globalSpend = await tracker.getCurrentSpend("global");
      expect(globalSpend).toBeGreaterThan(0);
    });
  });

  describe("records export", () => {
    it("returns all recorded costs", async () => {
      const tracker = new CostTracker({
        a: { softLimit: 100, hardLimit: 200, period: "daily" },
      });

      await tracker.recordCost("a", "gpt-4o", 1000, 500);
      await tracker.recordCost("a", "gpt-4o-mini", 2000, 1000);

      const records = tracker.getRecords();
      expect(records).toHaveLength(2);
    });
  });

  describe("getCurrentSpend", () => {
    it("returns 0 for unknown entity", async () => {
      const tracker = new CostTracker({});
      const spend = await tracker.getCurrentSpend("nobody");
      expect(spend).toBe(0);
    });
  });
});

describe("Model Pricing", () => {
  describe("getModelPricing", () => {
    it("returns exact match", () => {
      const pricing = getModelPricing("gpt-4o");
      expect(pricing.inputPer1M).toBe(2.5);
      expect(pricing.outputPer1M).toBe(10.0);
    });

    it("returns prefix match", () => {
      const pricing = getModelPricing("gpt-4o-2024-08-06");
      expect(pricing.inputPer1M).toBe(2.5);
    });

    it("returns Claude Opus pricing", () => {
      const pricing = getModelPricing("claude-opus-4-8");
      expect(pricing.inputPer1M).toBe(5.0);
      expect(pricing.outputPer1M).toBe(25.0);
    });

    it("returns Claude Fable 5 pricing", () => {
      const pricing = getModelPricing("claude-fable-5");
      expect(pricing.inputPer1M).toBe(10.0);
      expect(pricing.outputPer1M).toBe(50.0);
    });

    it("returns alias pricing", () => {
      const pricing = getModelPricing("sonnet");
      expect(pricing.inputPer1M).toBe(3.0);
    });

    it("falls back for unknown model", () => {
      const pricing = getModelPricing("unknown-model-xyz");
      expect(pricing.inputPer1M).toBe(0.15); // gpt-4o-mini fallback
    });
  });

  describe("estimateCost", () => {
    it("calculates cost correctly", () => {
      const cost = estimateCost("gpt-4o-mini", 1_000_000, 1_000_000);
      expect(cost).toBeCloseTo(0.75, 2); // 0.15 + 0.60
    });

    it("handles small token counts", () => {
      const cost = estimateCost("gpt-4o", 100, 50);
      expect(cost).toBeGreaterThan(0);
      expect(cost).toBeLessThan(0.01);
    });

    it("opus is most expensive", () => {
      const opus = estimateCost("claude-opus-4-6", 1000, 1000);
      const mini = estimateCost("gpt-4o-mini", 1000, 1000);
      expect(opus).toBeGreaterThan(mini);
    });
  });

  describe("MODEL_PRICING", () => {
    it("has OpenAI models", () => {
      expect(MODEL_PRICING["gpt-4o"]).toBeDefined();
      expect(MODEL_PRICING["gpt-4o-mini"]).toBeDefined();
      expect(MODEL_PRICING["o3"]).toBeDefined();
    });

    it("has Anthropic models", () => {
      expect(MODEL_PRICING["claude-fable-5"]).toBeDefined();
      expect(MODEL_PRICING["claude-opus-4-8"]).toBeDefined();
      expect(MODEL_PRICING["claude-opus-4-6"]).toBeDefined();
      expect(MODEL_PRICING["claude-sonnet-4-6"]).toBeDefined();
      expect(MODEL_PRICING["claude-haiku-4-5"]).toBeDefined();
    });
  });
});

describe("Anomaly Detection", () => {
  it("detects no anomaly with normal values", () => {
    const result = detectAnomaly(10, [8, 9, 10, 11, 12]);
    expect(result.isAnomaly).toBe(false);
  });

  it("detects anomaly with spike", () => {
    const result = detectAnomaly(100, [8, 9, 10, 11, 12, 10, 9]);
    expect(result.isAnomaly).toBe(true);
    expect(result.zScore).toBeGreaterThan(2.5);
  });

  it("returns no anomaly with insufficient data", () => {
    const result = detectAnomaly(100, [10, 20]);
    expect(result.isAnomaly).toBe(false); // <3 data points
  });

  it("handles constant history", () => {
    const result = detectAnomaly(15, [10, 10, 10, 10, 10]);
    expect(result.isAnomaly).toBe(true); // stdDev=0, any deviation is anomaly
  });

  it("same value as constant history is not anomaly", () => {
    const result = detectAnomaly(10, [10, 10, 10, 10]);
    expect(result.isAnomaly).toBe(false);
  });

  it("returns correct statistics", () => {
    const result = detectAnomaly(50, [10, 20, 30, 40, 50]);
    expect(result.currentValue).toBe(50);
    expect(result.mean).toBe(30);
    expect(result.stdDev).toBeGreaterThan(0);
  });

  it("respects custom threshold", () => {
    const result = detectAnomaly(30, [10, 10, 10, 10], 1.0); // low threshold
    expect(result.isAnomaly).toBe(true);
  });
});
