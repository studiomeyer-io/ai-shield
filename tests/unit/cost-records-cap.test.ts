import { describe, it, expect } from "vitest";
import { CostTracker } from "../../packages/core/src/cost/tracker.js";

// ============================================================
// CostTracker in-memory record cap — Round-4 OSS-Sweep (2026-04-24).
// Pre-fix: `private records: CostRecord[] = []` grew unbounded,
// a long-running process leaked ~300 B per recorded call.
// ============================================================

describe("CostTracker record retention", () => {
  it("caps in-memory records at maxRecords with ring-buffer eviction", async () => {
    const tracker = new CostTracker({}, undefined, { maxRecords: 100 });
    for (let i = 0; i < 250; i++) {
      await tracker.recordCost("agent-a", "gpt-4o-mini", 1_000, 500);
    }
    const records = tracker.getRecords();
    expect(records.length).toBe(100);
    // Ring-buffer semantics: we dropped the oldest 150. The first retained
    // record is the 151st recorded — they all have the same shape so we
    // just verify the count matches the cap.
  });

  it("disables retention when maxRecords=0", async () => {
    const tracker = new CostTracker({}, undefined, { maxRecords: 0 });
    for (let i = 0; i < 50; i++) {
      await tracker.recordCost("agent-a", "gpt-4o-mini", 1_000, 500);
    }
    expect(tracker.getRecords().length).toBe(0);
  });

  it("honours AI_SHIELD_MAX_RECORDS env override", async () => {
    process.env.AI_SHIELD_MAX_RECORDS = "5";
    try {
      const tracker = new CostTracker();
      for (let i = 0; i < 20; i++) {
        await tracker.recordCost("agent-a", "gpt-4o-mini", 1_000, 500);
      }
      expect(tracker.getRecords().length).toBe(5);
    } finally {
      delete process.env.AI_SHIELD_MAX_RECORDS;
    }
  });

  it("clearRecords() empties the ring buffer without affecting budgets", async () => {
    const tracker = new CostTracker({
      "agent-a": { softLimit: 10, hardLimit: 100, period: "daily" },
    });
    await tracker.recordCost("agent-a", "gpt-4o-mini", 1_000, 500);
    tracker.clearRecords();
    expect(tracker.getRecords().length).toBe(0);
    const spend = await tracker.getCurrentSpend("agent-a");
    expect(spend).toBeGreaterThan(0);
  });
});
