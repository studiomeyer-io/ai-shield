import { describe, it, expect } from "vitest";
import { PIIScanner } from "../../packages/core/src/scanner/pii.js";

// ============================================================
// IBAN coverage for short-country-code IBANs.
// Round-4 OSS-Sweep (2026-04-24)
// The v0.1.0 pattern was DE-biased (required five 4-digit groups),
// missing NO (15 chars), BE (16), NL (18), etc.
// ============================================================

describe("PIIScanner IBAN multi-country coverage", () => {
  const scanner = new PIIScanner();

  // All check digits below are real, mod-97-valid sample IBANs from
  // the IBAN Registry spec — see https://www.iban.com/structure
  const cases: Array<[string, string]> = [
    ["NO", "NO9386011117947"], // 15 chars
    ["BE", "BE68539007547034"], // 16 chars
    ["DK", "DK5000400440116243"], // 18 chars
    ["NL", "NL91ABNA0417164300"], // 18 chars
    ["DE", "DE89370400440532013000"], // 22 chars (unchanged from v0.1.0)
    ["FR", "FR1420041010050500013M02606"], // 27 chars
    ["MT", "MT84MALT011000012345MTLCAST001S"], // 31 chars
  ];

  for (const [country, iban] of cases) {
    it(`detects ${country} IBAN (${iban.length} chars): ${iban}`, () => {
      const entities = scanner.detect(iban);
      const ibans = entities.filter((e) => e.type === "iban");
      expect(
        ibans.length,
        `IBAN for ${country} not detected`,
      ).toBeGreaterThanOrEqual(1);
      expect(ibans[0]!.confidence).toBeGreaterThanOrEqual(0.9);
    });
  }

  it("accepts human-grouped DE IBAN with 4-digit chunks", () => {
    const grouped = "Meine IBAN lautet DE89 3704 0044 0532 0130 00";
    const entities = scanner.detect(grouped);
    const ibans = entities.filter((e) => e.type === "iban");
    expect(ibans.length).toBeGreaterThanOrEqual(1);
  });

  it("rejects IBAN-shaped string with broken mod-97 checksum", () => {
    // DE89 with scrambled body — fails mod-97
    const fake = "DE99XXXXXXXXXXXXXXXXXX";
    const entities = scanner.detect(fake);
    const ibans = entities.filter((e) => e.type === "iban");
    expect(ibans.length).toBe(0);
  });

  it("does not match random 22-char alphanumerics", () => {
    const noise = "AA00ZZZZZZZZZZZZZZZZZZ";
    const entities = scanner.detect(noise);
    const ibans = entities.filter((e) => e.type === "iban");
    expect(ibans.length).toBe(0);
  });
});

describe("PIIScanner phone masking edge cases", () => {
  const scanner = new PIIScanner({ action: "mask" });

  it("masks a normal phone without overlap", async () => {
    const input = "Call me at +49 30 12345678";
    const result = await scanner.scan(input, {});
    expect(result.sanitized).toContain("****");
    expect(result.sanitized).not.toContain("12345678");
  });

  it("masks minimum-length phone number without overlap", async () => {
    // Phone validator requires 7+ digits. "+49 30 1234" is 7 digits post-strip.
    const input = "Ruf an: +49 30 1234";
    const result = await scanner.scan(input, {});
    // Either a proper mask or the generic [PHONE] token — never a garbled overlap
    // like "****6*4"s that the old substring math produced.
    expect(result.sanitized).not.toMatch(/\*\*\*\*[^*\s].*\*\*\*\*/);
  });
});
