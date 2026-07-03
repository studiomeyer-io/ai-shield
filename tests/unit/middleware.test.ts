import { describe, it, expect } from "vitest";
import {
  defaultGetInput,
  defaultBlockedResponse,
} from "../../packages/middleware/src/shared.js";
import type { ScanResult } from "../../packages/core/src/types.js";

describe("Middleware Shared", () => {
  describe("defaultGetInput", () => {
    it("extracts message field", () => {
      expect(defaultGetInput({ message: "hello" })).toBe("hello");
    });

    it("extracts input field", () => {
      expect(defaultGetInput({ input: "hello" })).toBe("hello");
    });

    it("extracts prompt field", () => {
      expect(defaultGetInput({ prompt: "hello" })).toBe("hello");
    });

    it("extracts text field", () => {
      expect(defaultGetInput({ text: "hello" })).toBe("hello");
    });

    it("extracts content field", () => {
      expect(defaultGetInput({ content: "hello" })).toBe("hello");
    });

    it("extracts query field", () => {
      expect(defaultGetInput({ query: "hello" })).toBe("hello");
    });

    it("extracts from OpenAI-style messages array", () => {
      const body = {
        messages: [
          { role: "system", content: "You are helpful." },
          { role: "user", content: "What is AI?" },
          { role: "assistant", content: "AI is..." },
          { role: "user", content: "Tell me more." },
        ],
      };
      expect(defaultGetInput(body)).toBe("What is AI?\nTell me more.");
    });

    it("returns null for empty body", () => {
      expect(defaultGetInput(null)).toBeNull();
      expect(defaultGetInput(undefined)).toBeNull();
      expect(defaultGetInput({})).toBeNull();
    });

    it("returns null for non-object body", () => {
      expect(defaultGetInput("string")).toBeNull();
      expect(defaultGetInput(42)).toBeNull();
    });

    it("ignores non-user messages", () => {
      const body = {
        messages: [
          { role: "system", content: "System prompt" },
          { role: "assistant", content: "Previous response" },
        ],
      };
      expect(defaultGetInput(body)).toBeNull();
    });

    it("prioritizes direct fields over messages array", () => {
      const body = {
        message: "direct",
        messages: [{ role: "user", content: "from array" }],
      };
      expect(defaultGetInput(body)).toBe("direct");
    });
  });

  describe("defaultBlockedResponse", () => {
    it("returns 403 with violations", () => {
      const scanResult: ScanResult = {
        safe: false,
        decision: "block",
        sanitized: "",
        violations: [
          {
            type: "prompt_injection",
            scanner: "heuristic",
            score: 0.8,
            threshold: 0.3,
            message: "Injection detected",
          },
        ],
        meta: { scanDurationMs: 1, scannersRun: ["heuristic"], cached: false },
      };

      const response = defaultBlockedResponse(scanResult);
      expect(response.status).toBe(403);

      const body = response.body as {
        error: string;
        decision: string;
        violations: Array<{ type: string; message: string }>;
      };
      expect(body.error).toBe("Request blocked by AI Shield");
      expect(body.decision).toBe("block");
      expect(body.violations).toHaveLength(1);
      expect(body.violations[0]!.type).toBe("prompt_injection");
      expect(body.violations[0]!.message).toBe("Injection detected");
    });

    it("maps multiple violations", () => {
      const scanResult: ScanResult = {
        safe: false,
        decision: "block",
        sanitized: "",
        violations: [
          {
            type: "prompt_injection",
            scanner: "heuristic",
            score: 0.8,
            threshold: 0.3,
            message: "Injection",
          },
          {
            type: "pii_detected",
            scanner: "pii",
            score: 0.95,
            threshold: 0,
            message: "PII found",
          },
        ],
        meta: {
          scanDurationMs: 2,
          scannersRun: ["heuristic", "pii"],
          cached: false,
        },
      };

      const response = defaultBlockedResponse(scanResult);
      const body = response.body as { violations: Array<{ type: string }> };
      expect(body.violations).toHaveLength(2);
    });
  });
});
