import { describe, it, expect } from "vitest";
import { ScannerChain } from "../../packages/core/src/scanner/chain.js";
import type {
  Scanner,
  ScannerResult,
  ScanContext,
} from "../../packages/core/src/types.js";

// --- Mock scanners ---

function mockScanner(
  name: string,
  decision: "allow" | "warn" | "block",
  sanitized?: string,
): Scanner {
  return {
    name,
    async scan(_input: string, _ctx: ScanContext): Promise<ScannerResult> {
      return {
        decision,
        violations:
          decision !== "allow"
            ? [
                {
                  type: "prompt_injection",
                  scanner: name,
                  score: decision === "block" ? 1.0 : 0.5,
                  threshold: 0.3,
                  message: `${name} flagged`,
                },
              ]
            : [],
        sanitized,
        durationMs: 0.1,
      };
    },
  };
}

describe("ScannerChain", () => {
  describe("basic chain execution", () => {
    it("runs all scanners in sequence", async () => {
      const chain = new ScannerChain();
      chain.add(mockScanner("a", "allow"));
      chain.add(mockScanner("b", "allow"));
      chain.add(mockScanner("c", "allow"));

      const result = await chain.run("hello");
      expect(result.safe).toBe(true);
      expect(result.decision).toBe("allow");
      expect(result.meta.scannersRun).toEqual(["a", "b", "c"]);
    });

    it("returns empty chain as allow", async () => {
      const chain = new ScannerChain();
      const result = await chain.run("hello");
      expect(result.safe).toBe(true);
      expect(result.meta.scannersRun).toEqual([]);
    });

    it("single scanner works", async () => {
      const chain = new ScannerChain();
      chain.add(mockScanner("solo", "warn"));
      const result = await chain.run("test");
      expect(result.decision).toBe("warn");
      expect(result.safe).toBe(false);
    });
  });

  describe("decision escalation", () => {
    it("escalates allow → warn", async () => {
      const chain = new ScannerChain({ earlyExit: false });
      chain.add(mockScanner("a", "allow"));
      chain.add(mockScanner("b", "warn"));

      const result = await chain.run("test");
      expect(result.decision).toBe("warn");
    });

    it("escalates warn → block", async () => {
      const chain = new ScannerChain({ earlyExit: false });
      chain.add(mockScanner("a", "warn"));
      chain.add(mockScanner("b", "block"));

      const result = await chain.run("test");
      expect(result.decision).toBe("block");
    });

    it("does not de-escalate block → allow", async () => {
      const chain = new ScannerChain({ earlyExit: false });
      chain.add(mockScanner("a", "block"));
      chain.add(mockScanner("b", "allow"));

      const result = await chain.run("test");
      expect(result.decision).toBe("block");
    });
  });

  describe("early exit", () => {
    it("stops on block when earlyExit=true", async () => {
      const chain = new ScannerChain({ earlyExit: true });
      chain.add(mockScanner("a", "block"));
      chain.add(mockScanner("b", "allow"));

      const result = await chain.run("test");
      expect(result.decision).toBe("block");
      expect(result.meta.scannersRun).toEqual(["a"]); // b was NOT run
    });

    it("continues on block when earlyExit=false", async () => {
      const chain = new ScannerChain({ earlyExit: false });
      chain.add(mockScanner("a", "block"));
      chain.add(mockScanner("b", "allow"));

      const result = await chain.run("test");
      expect(result.decision).toBe("block");
      expect(result.meta.scannersRun).toEqual(["a", "b"]); // both ran
    });

    it("does NOT early-exit on warn", async () => {
      const chain = new ScannerChain({ earlyExit: true });
      chain.add(mockScanner("a", "warn"));
      chain.add(mockScanner("b", "allow"));

      const result = await chain.run("test");
      expect(result.meta.scannersRun).toEqual(["a", "b"]);
    });
  });

  describe("sanitization", () => {
    it("passes sanitized text through chain", async () => {
      const chain = new ScannerChain();
      chain.add(mockScanner("mask", "warn", "MASKED"));
      chain.add(mockScanner("check", "allow"));

      const result = await chain.run("original");
      expect(result.sanitized).toBe("MASKED");
    });

    it("preserves original when no sanitization", async () => {
      const chain = new ScannerChain();
      chain.add(mockScanner("a", "allow"));

      const result = await chain.run("original text");
      expect(result.sanitized).toBe("original text");
    });
  });

  describe("violations", () => {
    it("collects violations from all scanners", async () => {
      const chain = new ScannerChain({ earlyExit: false });
      chain.add(mockScanner("a", "warn"));
      chain.add(mockScanner("b", "warn"));

      const result = await chain.run("test");
      expect(result.violations).toHaveLength(2);
      expect(result.violations[0]!.scanner).toBe("a");
      expect(result.violations[1]!.scanner).toBe("b");
    });
  });

  describe("metadata", () => {
    it("tracks total scan duration", async () => {
      const chain = new ScannerChain();
      chain.add(mockScanner("a", "allow"));
      const result = await chain.run("test");
      expect(result.meta.scanDurationMs).toBeGreaterThanOrEqual(0);
    });

    it("reports cached as false", async () => {
      const chain = new ScannerChain();
      const result = await chain.run("test");
      expect(result.meta.cached).toBe(false);
    });
  });

  describe("chain length", () => {
    it("tracks scanner count", () => {
      const chain = new ScannerChain();
      expect(chain.length).toBe(0);
      chain.add(mockScanner("a", "allow"));
      expect(chain.length).toBe(1);
      chain.add(mockScanner("b", "allow"));
      expect(chain.length).toBe(2);
    });
  });
});
