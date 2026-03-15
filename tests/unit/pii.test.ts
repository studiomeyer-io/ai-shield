import { describe, it, expect } from "vitest";
import { PIIScanner } from "../../packages/core/src/scanner/pii.js";

describe("PIIScanner", () => {
  const scanner = new PIIScanner({ action: "mask" });

  describe("detects German IBAN", () => {
    it("detects valid DE IBAN", () => {
      const entities = scanner.detect("Meine IBAN ist DE89 3704 0044 0532 0130 00");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("iban");
      expect(entities[0]!.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it("detects IBAN without spaces", () => {
      const entities = scanner.detect("IBAN: DE89370400440532013000");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("iban");
    });

    it("rejects invalid IBAN checksum", () => {
      const entities = scanner.detect("IBAN: DE00 1234 5678 9012 3456 78");
      expect(entities).toHaveLength(0);
    });
  });

  describe("detects credit cards", () => {
    it("detects Visa", () => {
      const entities = scanner.detect("Card: 4111 1111 1111 1111");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("credit_card");
    });

    it("detects Mastercard", () => {
      const entities = scanner.detect("MC: 5500-0000-0000-0004");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("credit_card");
    });

    it("rejects invalid Luhn", () => {
      const entities = scanner.detect("Number: 1234 5678 9012 3456");
      expect(entities).toHaveLength(0);
    });
  });

  describe("detects email", () => {
    it("detects standard email", () => {
      const entities = scanner.detect("Contact: user@example.com");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("email");
    });

    it("detects email with subdomain", () => {
      const entities = scanner.detect("Send to hello@mail.example.com");
      expect(entities).toHaveLength(1);
    });
  });

  describe("detects German phone numbers", () => {
    it("detects +49 format", () => {
      const entities = scanner.detect("Tel: +49 171 1234567");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("phone");
    });

    it("detects 0-prefix format", () => {
      const entities = scanner.detect("Ruf an: 0171/1234567");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("phone");
    });

    it("detects landline with area code", () => {
      const entities = scanner.detect("Buero: 030 12345678");
      expect(entities).toHaveLength(1);
    });
  });

  describe("detects German tax ID", () => {
    it("detects Steuer-ID format", () => {
      const entities = scanner.detect("Steuer-ID: 12 345 678 901");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("german_tax_id");
    });
  });

  describe("detects IP addresses", () => {
    it("detects public IP", () => {
      const entities = scanner.detect("Server: 203.0.113.42");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("ip_address");
    });

    it("ignores private IPs", () => {
      const entities = scanner.detect("Local: 192.168.1.1 and 10.0.0.1");
      expect(entities).toHaveLength(0);
    });
  });

  describe("detects URLs with credentials", () => {
    it("detects embedded auth", () => {
      const entities = scanner.detect("DB: https://admin:secret@db.example.com/mydb");
      expect(entities).toHaveLength(1);
      expect(entities[0]!.type).toBe("url_with_credentials");
    });
  });

  describe("masking", () => {
    it("masks PII in text", async () => {
      const result = await scanner.scan(
        "Kontakt: user@example.com, Tel +49 171 1234567, IBAN DE89 3704 0044 0532 0130 00",
        {},
      );
      expect(result.sanitized).not.toContain("user@example.com");
      expect(result.sanitized).not.toContain("DE89 3704 0044 0532 0130 00");
      expect(result.sanitized).toContain("u***@example.com");
    });

    it("returns warn decision for masked content", async () => {
      const result = await scanner.scan("Email: test@example.com", {});
      expect(result.decision).toBe("warn");
      expect(result.violations).toHaveLength(1);
    });
  });

  describe("allowed types", () => {
    it("skips allowed types", async () => {
      const permissive = new PIIScanner({ action: "mask", allowedTypes: ["email"] });
      const result = await permissive.scan("Email: test@example.com", {});
      expect(result.decision).toBe("allow");
    });
  });

  describe("block mode", () => {
    it("blocks when action is block", async () => {
      const strict = new PIIScanner({ action: "block" });
      const result = await strict.scan("IBAN: DE89 3704 0044 0532 0130 00", {});
      expect(result.decision).toBe("block");
    });
  });

  describe("performance", () => {
    it("scans in under 10ms", async () => {
      const text = "This is a long text without PII. ".repeat(200);
      const result = await scanner.scan(text, {});
      expect(result.durationMs).toBeLessThan(10);
    });
  });
});
