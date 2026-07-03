import { describe, it, expect } from "vitest";
import { PolicyEngine } from "../../packages/core/src/policy/engine.js";

describe("PolicyEngine", () => {
  describe("presets", () => {
    it("loads public_website preset", () => {
      const engine = new PolicyEngine("public_website");
      const preset = engine.getPreset();
      expect(preset.name).toBe("public_website");
      expect(preset.injection.threshold).toBe(0.25);
    });

    it("loads internal_support preset", () => {
      const engine = new PolicyEngine("internal_support");
      expect(engine.getInjectionThreshold()).toBe(0.35);
    });

    it("loads ops_agent preset", () => {
      const engine = new PolicyEngine("ops_agent");
      expect(engine.getInjectionThreshold()).toBe(0.5);
    });

    it("defaults to public_website", () => {
      const engine = new PolicyEngine();
      expect(engine.getPreset().name).toBe("public_website");
    });
  });

  describe("injection thresholds", () => {
    it("public is strictest (lowest threshold)", () => {
      const pub = new PolicyEngine("public_website");
      const int = new PolicyEngine("internal_support");
      const ops = new PolicyEngine("ops_agent");

      expect(pub.getInjectionThreshold()).toBeLessThan(
        int.getInjectionThreshold(),
      );
      expect(int.getInjectionThreshold()).toBeLessThan(
        ops.getInjectionThreshold(),
      );
    });
  });

  describe("PII actions", () => {
    it("public_website blocks credit cards", () => {
      const engine = new PolicyEngine("public_website");
      expect(engine.getPIIAction("creditCard")).toBe("block");
    });

    it("public_website blocks IBANs", () => {
      const engine = new PolicyEngine("public_website");
      expect(engine.getPIIAction("iban")).toBe("block");
    });

    it("ops_agent allows email", () => {
      const engine = new PolicyEngine("ops_agent");
      expect(engine.getPIIAction("email")).toBe("allow");
    });

    it("internal_support masks everything", () => {
      const engine = new PolicyEngine("internal_support");
      expect(engine.getPIIAction("email")).toBe("mask");
      expect(engine.getPIIAction("creditCard")).toBe("mask");
      expect(engine.getPIIAction("iban")).toBe("mask");
    });

    it("returns default action for unknown type", () => {
      const engine = new PolicyEngine("public_website");
      expect(engine.getPIIAction()).toBe("mask");
    });
  });

  describe("tool policies", () => {
    it("public_website has most dangerous patterns", () => {
      const pub = new PolicyEngine("public_website");
      const ops = new PolicyEngine("ops_agent");

      expect(pub.getDangerousToolPatterns().length).toBeGreaterThan(
        ops.getDangerousToolPatterns().length,
      );
    });

    it("public_website has lowest chain depth", () => {
      const pub = new PolicyEngine("public_website");
      const ops = new PolicyEngine("ops_agent");

      expect(pub.getMaxToolChainDepth()).toBeLessThan(
        ops.getMaxToolChainDepth(),
      );
    });
  });

  describe("cost budgets", () => {
    it("public has lowest daily budget", () => {
      const pub = new PolicyEngine("public_website");
      const ops = new PolicyEngine("ops_agent");

      expect(pub.getDailyBudget()).toBeLessThan(ops.getDailyBudget());
    });

    it("ops has $100 daily budget", () => {
      const ops = new PolicyEngine("ops_agent");
      expect(ops.getDailyBudget()).toBe(100);
    });
  });

  describe("static methods", () => {
    it("lists all preset names", () => {
      const names = PolicyEngine.getPresetNames();
      expect(names).toContain("public_website");
      expect(names).toContain("internal_support");
      expect(names).toContain("ops_agent");
      expect(names).toHaveLength(3);
    });

    it("gets preset by name", () => {
      const preset = PolicyEngine.getPreset("ops_agent");
      expect(preset.name).toBe("ops_agent");
    });
  });
});
