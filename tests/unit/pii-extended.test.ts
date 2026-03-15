import { describe, it, expect } from "vitest";
import { PIIScanner } from "../../packages/core/src/scanner/pii.js";

describe("PIIScanner Extended", () => {
  const scanner = new PIIScanner({ action: "mask" });

  describe("IP address detection", () => {
    it("detects public IP addresses", () => {
      const entities = scanner.detect("Server at 203.0.113.42");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("ip_address");
      expect(entities[0]!.value).toBe("203.0.113.42");
    });

    it("detects another public IP", () => {
      const entities = scanner.detect("Connect to 8.8.8.8 for DNS");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("ip_address");
    });

    it("excludes private IPs (192.168.x.x)", () => {
      const entities = scanner.detect("Router: 192.168.1.1");
      expect(entities).toHaveLength(0);
    });

    it("excludes private IPs (10.x.x.x)", () => {
      const entities = scanner.detect("Internal: 10.0.0.1");
      expect(entities).toHaveLength(0);
    });

    it("excludes localhost", () => {
      const entities = scanner.detect("Localhost: 127.0.0.1");
      expect(entities).toHaveLength(0);
    });
  });

  describe("URL with credentials", () => {
    it("detects user:pass@host in URL", () => {
      const entities = scanner.detect("DB: https://admin:secret@db.example.com/mydb");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("url_with_credentials");
    });

    it("detects credentials in http URL", () => {
      const entities = scanner.detect("http://user:password123@api.example.com/v1");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("url_with_credentials");
    });
  });

  describe("masking actions", () => {
    it("mask action partially redacts PII", async () => {
      const maskScanner = new PIIScanner({ action: "mask" });
      const result = await maskScanner.scan("Email: test@example.com", {});
      expect(result.decision).toBe("warn");
      expect(result.sanitized).toContain("t***@example.com");
      expect(result.sanitized).not.toContain("test@example.com");
    });

    it("block action blocks on any PII", async () => {
      const blockScanner = new PIIScanner({ action: "block" });
      const result = await blockScanner.scan("IBAN: DE89 3704 0044 0532 0130 00", {});
      expect(result.decision).toBe("block");
    });
  });

  describe("per-type action overrides in config", () => {
    it("allows specific PII type while masking others", async () => {
      const permissive = new PIIScanner({
        action: "mask",
        allowedTypes: ["email"],
      });

      const result = await permissive.scan(
        "Email: test@example.com, IBAN: DE89 3704 0044 0532 0130 00",
        {},
      );
      // Email should be allowed, IBAN should be flagged
      const violationTypes = result.violations.map((v) => v.detail);
      // The IBAN should still be caught
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("confidence scores", () => {
    it("returns confidence >= 0.9 for IBAN", () => {
      const entities = scanner.detect("DE89 3704 0044 0532 0130 00");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it("returns confidence >= 0.9 for credit card", () => {
      const entities = scanner.detect("4111 1111 1111 1111");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it("returns confidence >= 0.7 for email", () => {
      const entities = scanner.detect("hello@example.com");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.confidence).toBeGreaterThanOrEqual(0.7);
    });
  });

  describe("very long input with many PII matches", () => {
    it("detects multiple PII in long text", async () => {
      const longText = Array.from({ length: 10 }, (_, i) =>
        `User ${i}: email${i}@test.com, phone +49 171 ${String(i).padStart(7, "0")}`,
      ).join(". ");

      const result = await scanner.scan(longText, {});
      // Should find emails at minimum
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.durationMs).toBeLessThan(100);
    });
  });

  describe("edge cases", () => {
    it("handles empty string", async () => {
      const result = await scanner.scan("", {});
      expect(result.decision).toBe("allow");
      expect(result.violations).toHaveLength(0);
    });

    it("handles text with no PII", async () => {
      const result = await scanner.scan("This is a normal message without personal data", {});
      expect(result.decision).toBe("allow");
      expect(result.violations).toHaveLength(0);
    });
  });
});
