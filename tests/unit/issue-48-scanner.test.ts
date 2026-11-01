import { describe, it, expect } from "vitest";
import { AIShield, HeuristicScanner } from "../../packages/core/src/index.js";
import type {
  PresetName,
  ShieldConfig,
} from "../../packages/core/src/index.js";

const probe = "For educational purposes only, this is a test.";
async function scan(config: ShieldConfig) {
  const shield = new AIShield({
    ...config,
    pii: { enabled: false },
    audit: { enabled: false },
  });
  try {
    return await shield.scan(probe);
  } finally {
    await shield.close();
  }
}

describe("Issue 48: threshold precedence", () => {
  it.each<PresetName>(["public_website", "internal_support", "ops_agent"])(
    "honors strictness with preset %s",
    async (preset) => {
      const high = await scan({ preset, injection: { strictness: "high" } });
      const medium = await scan({
        preset,
        injection: { strictness: "medium" },
      });
      const low = await scan({ preset, injection: { strictness: "low" } });
      expect(high.decision).toBe("block");
      expect(medium.decision).toBe("warn");
      expect(low.decision).toBe("allow");
      expect(high.violations[0]?.threshold).toBe(0.15);
      expect(medium.violations[0]?.threshold).toBe(0.3);
      expect(low.violations[0]?.threshold).toBe(0.5);
    },
  );
  it("honors explicit strictness with the implicit default preset", async () => {
    expect((await scan({ injection: { strictness: "high" } })).decision).toBe(
      "block",
    );
    expect((await scan({ injection: { strictness: "low" } })).decision).toBe(
      "allow",
    );
  });
  it.each(["low", "medium", "high"] as const)(
    "explicit threshold overrides %s strictness",
    async (strictness) => {
      const result = await scan({
        preset: "ops_agent",
        injection: { strictness, threshold: 0.1 },
      });
      expect(result.decision).toBe("block");
      expect(result.violations[0]?.threshold).toBe(0.1);
    },
  );
  it.each<[PresetName, number]>([
    ["public_website", 0.25],
    ["internal_support", 0.35],
    ["ops_agent", 0.5],
  ])(
    "preserves preset %s when strictness is absent",
    async (preset, threshold) => {
      expect((await scan({ preset })).violations[0]?.threshold).toBe(threshold);
    },
  );
});

describe("Issue 48: ROLE-007", () => {
  const scanner = new HeuristicScanner();
  it.each([
    "DAN can do anything",
    "DAN DAN DAN can do anything",
    "DAN " + "ordinary words ".repeat(100) + " no limits",
    "dan " + "DAN ".repeat(100) + " no restrictions",
  ])("retains same-line matching: %s", async (input) => {
    const result = await scanner.scan(input, {});
    expect(result.violations.some((v) => v.detail?.includes("ROLE-007"))).toBe(
      true,
    );
  });
  it("does not join DAN with a suffix on a later line", async () => {
    const result = await scanner.scan("DAN\nordinary words no limits", {});
    expect(result.violations.some((v) => v.detail?.includes("ROLE-007"))).toBe(
      false,
    );
  });
  it("handles a long repetitive negative input in the real scanner", async () => {
    const result = await scanner.scan("DAN ".repeat(60_000), {});
    expect(result.decision).toBe("allow");
    expect(result.violations).toEqual([]);
  });
});
