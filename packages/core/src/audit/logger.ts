import { randomUUID } from "node:crypto";
import { createHash } from "node:crypto";
import type { AuditRecord, ScanResult, ScanContext } from "../types.js";
import type { AuditStore } from "./types.js";

// ============================================================
// Audit Logger — Batched writes to pluggable backend
// Stores metadata + hashes, NOT raw content (DSGVO)
// ============================================================

export interface AuditLoggerConfig {
  store: AuditStore;
  batchSize?: number;
  flushIntervalMs?: number;
}

export class AuditLogger {
  private store: AuditStore;
  private buffer: AuditRecord[] = [];
  private batchSize: number;
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: AuditLoggerConfig) {
    this.store = config.store;
    this.batchSize = config.batchSize ?? 100;
    const flushMs = config.flushIntervalMs ?? 1000;

    this.flushTimer = setInterval(() => {
      void this.flush();
    }, flushMs);
    // Allow the Node process to exit even if the timer is pending —
    // clean shutdown should go through close(), not rely on the timer.
    if (typeof this.flushTimer.unref === "function") {
      this.flushTimer.unref();
    }
  }

  /** Log a scan result */
  async log(
    input: string,
    result: ScanResult,
    context: ScanContext = {},
    extra: {
      model?: string;
      outputTokenCount?: number;
      toolsCalled?: string[];
      costUsd?: number;
    } = {},
  ): Promise<void> {
    const record: AuditRecord = {
      id: randomUUID(),
      timestamp: new Date(),
      sessionId: context.sessionId,
      agentId: context.agentId,
      userIdHash: context.userId
        ? createHash("sha256").update(context.userId).digest("hex").substring(0, 32)
        : undefined,
      requestType: context.tools?.length ? "tool_call" : "chat",
      inputHash: createHash("sha256").update(input).digest("hex"),
      inputTokenCount: Math.ceil(input.length / 4), // rough estimate
      model: extra.model,
      securityDecision: result.decision,
      securityReason: result.violations.length > 0
        ? result.violations.map((v) => v.message).join("; ")
        : undefined,
      violations: result.violations,
      scanDurationMs: result.meta.scanDurationMs,
      outputTokenCount: extra.outputTokenCount,
      toolsCalled: extra.toolsCalled,
      costUsd: extra.costUsd,
    };

    this.buffer.push(record);

    if (this.buffer.length >= this.batchSize) {
      await this.flush();
    }
  }

  /** Flush buffered records to store */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const batch = this.buffer.splice(0);
    await this.store.writeBatch(batch);
  }

  /** Close the logger (flush + stop timer) */
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
    await this.store.close();
  }
}

// --- Console Store (for development) ---

export class ConsoleAuditStore implements AuditStore {
  async write(record: AuditRecord): Promise<void> {
    this.print(record);
  }

  async writeBatch(records: AuditRecord[]): Promise<void> {
    for (const record of records) this.print(record);
  }

  async flush(): Promise<void> { /* noop */ }
  async close(): Promise<void> { /* noop */ }

  private print(record: AuditRecord): void {
    const icon = record.securityDecision === "block" ? "BLOCK" : record.securityDecision === "warn" ? "WARN " : "ALLOW";
    const violations = record.violations.length > 0
      ? ` [${record.violations.map((v) => v.message).join(", ")}]`
      : "";
    // Using stderr to not interfere with application output
    process.stderr.write(
      `[AI-Shield] ${icon} | ${record.scanDurationMs.toFixed(1)}ms | agent=${record.agentId ?? "-"} | ${record.inputHash.substring(0, 8)}...${violations}\n`,
    );
  }
}

// --- Memory Store (for testing) ---

export class MemoryAuditStore implements AuditStore {
  records: AuditRecord[] = [];

  async write(record: AuditRecord): Promise<void> {
    this.records.push(record);
  }

  async writeBatch(records: AuditRecord[]): Promise<void> {
    this.records.push(...records);
  }

  async flush(): Promise<void> { /* noop */ }
  async close(): Promise<void> { /* noop */ }
}
