import { describe, it, expect, afterEach } from "vitest";
import { AuditLogger, MemoryAuditStore } from "../../packages/core/src/audit/logger.js";
import type { ScanResult } from "../../packages/core/src/types.js";

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    safe: true,
    decision: "allow",
    sanitized: "test input",
    violations: [],
    meta: { scanDurationMs: 1.5, scannersRun: ["heuristic", "pii"], cached: false },
    ...overrides,
  };
}

describe("AuditLogger", () => {
  let logger: AuditLogger | null = null;

  afterEach(async () => {
    if (logger) {
      await logger.close();
      logger = null;
    }
  });

  describe("logging", () => {
    it("logs a scan result", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test input", makeScanResult());
      await logger.flush();

      expect(store.records).toHaveLength(1);
      expect(store.records[0]!.securityDecision).toBe("allow");
    });

    it("hashes input instead of storing raw", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("sensitive user input", makeScanResult());
      await logger.flush();

      const record = store.records[0]!;
      expect(record.inputHash).toBeDefined();
      expect(record.inputHash).toHaveLength(64); // SHA-256 hex
      expect(record.inputHash).not.toContain("sensitive");
    });

    it("hashes user ID", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test", makeScanResult(), { userId: "user-123" });
      await logger.flush();

      const record = store.records[0]!;
      expect(record.userIdHash).toBeDefined();
      expect(record.userIdHash).not.toContain("user-123");
      expect(record.userIdHash!.length).toBe(32); // 128-bit truncated SHA-256 (collision-resistant to ~2^64)
    });

    it("stores agent ID and session ID", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test", makeScanResult(), {
        agentId: "chatbot",
        sessionId: "sess-abc",
      });
      await logger.flush();

      const record = store.records[0]!;
      expect(record.agentId).toBe("chatbot");
      expect(record.sessionId).toBe("sess-abc");
    });

    it("detects tool_call request type", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test", makeScanResult(), {
        tools: [{ name: "search_knowledge" }],
      });
      await logger.flush();

      expect(store.records[0]!.requestType).toBe("tool_call");
    });

    it("defaults to chat request type", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test", makeScanResult());
      await logger.flush();

      expect(store.records[0]!.requestType).toBe("chat");
    });

    it("stores violations", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test", makeScanResult({
        decision: "block",
        safe: false,
        violations: [{
          type: "prompt_injection",
          scanner: "heuristic",
          score: 0.8,
          threshold: 0.3,
          message: "Injection detected",
        }],
      }));
      await logger.flush();

      const record = store.records[0]!;
      expect(record.securityDecision).toBe("block");
      expect(record.violations).toHaveLength(1);
      expect(record.securityReason).toContain("Injection detected");
    });

    it("stores extra metadata", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("test", makeScanResult(), {}, {
        model: "gpt-4o",
        outputTokenCount: 150,
        toolsCalled: ["search_knowledge"],
        costUsd: 0.003,
      });
      await logger.flush();

      const record = store.records[0]!;
      expect(record.model).toBe("gpt-4o");
      expect(record.outputTokenCount).toBe(150);
      expect(record.toolsCalled).toEqual(["search_knowledge"]);
      expect(record.costUsd).toBe(0.003);
    });
  });

  describe("batching", () => {
    it("flushes at batch size", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, batchSize: 3, flushIntervalMs: 60000 });

      await logger.log("a", makeScanResult());
      await logger.log("b", makeScanResult());
      expect(store.records).toHaveLength(0); // not flushed yet

      await logger.log("c", makeScanResult()); // triggers flush at batchSize=3
      expect(store.records).toHaveLength(3);
    });

    it("flush clears buffer", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, flushIntervalMs: 60000 });

      await logger.log("a", makeScanResult());
      await logger.flush();
      expect(store.records).toHaveLength(1);

      await logger.flush(); // second flush does nothing
      expect(store.records).toHaveLength(1);
    });
  });

  describe("close", () => {
    it("flushes remaining records on close", async () => {
      const store = new MemoryAuditStore();
      logger = new AuditLogger({ store, batchSize: 100, flushIntervalMs: 60000 });

      await logger.log("a", makeScanResult());
      await logger.log("b", makeScanResult());
      expect(store.records).toHaveLength(0);

      await logger.close();
      logger = null; // prevent double close in afterEach
      expect(store.records).toHaveLength(2);
    });
  });
});

describe("MemoryAuditStore", () => {
  it("stores single record", async () => {
    const store = new MemoryAuditStore();
    const record = { id: "1" } as any;
    await store.write(record);
    expect(store.records).toHaveLength(1);
  });

  it("stores batch of records", async () => {
    const store = new MemoryAuditStore();
    await store.writeBatch([{ id: "1" } as any, { id: "2" } as any]);
    expect(store.records).toHaveLength(2);
  });
});
