import { describe, it, expect } from "vitest";
import { ToolPolicyScanner } from "../../packages/core/src/policy/tools.js";
import type {
  ToolPolicy,
  ToolManifestPin,
} from "../../packages/core/src/types.js";

describe("ToolPolicyScanner", () => {
  const policy: ToolPolicy = {
    permissions: {
      "support-agent": {
        allowed: ["search_*", "get_*", "create_ticket"],
        denied: ["delete_*", "admin_*", "billing_*"],
      },
      "customer-bot": {
        allowed: ["search_knowledge", "get_portfolio", "get_pricing"],
      },
    },
    global: {
      dangerousPatterns: ["execute_shell", "drop_*", "destroy_*"],
      maxToolChainDepth: 5,
    },
  };

  const scanner = new ToolPolicyScanner(policy);

  describe("permission checks", () => {
    it("allows permitted tools", async () => {
      const result = await scanner.scan("", {
        agentId: "support-agent",
        tools: [{ name: "search_knowledge" }],
      });
      expect(result.decision).toBe("allow");
    });

    it("blocks denied tools", async () => {
      const result = await scanner.scan("", {
        agentId: "support-agent",
        tools: [{ name: "delete_user" }],
      });
      expect(result.decision).toBe("block");
      expect(result.violations[0]!.type).toBe("tool_denied");
    });

    it("blocks tools not in allow list", async () => {
      const result = await scanner.scan("", {
        agentId: "customer-bot",
        tools: [{ name: "send_email" }],
      });
      expect(result.decision).toBe("block");
    });

    it("blocks globally dangerous tools", async () => {
      const result = await scanner.scan("", {
        agentId: "support-agent",
        tools: [{ name: "execute_shell" }],
      });
      expect(result.decision).toBe("block");
    });

    it("supports wildcard matching", async () => {
      const result = await scanner.scan("", {
        agentId: "support-agent",
        tools: [{ name: "get_project_status" }],
      });
      expect(result.decision).toBe("allow");
    });
  });

  describe("manifest pinning", () => {
    it("creates manifest pin", () => {
      const pin = ToolPolicyScanner.pinManifest("mcp-crm", [
        "create_lead",
        "get_leads",
        "search_leads",
        "delete_lead",
      ]);
      expect(pin.serverId).toBe("mcp-crm");
      expect(pin.toolCount).toBe(4);
      expect(pin.toolsHash).toHaveLength(64); // SHA-256 hex
      expect(pin.knownTools).toEqual([
        "create_lead",
        "delete_lead",
        "get_leads",
        "search_leads",
      ]); // sorted
    });

    it("detects manifest drift — added tools", () => {
      const pin = ToolPolicyScanner.pinManifest("mcp-crm", [
        "create_lead",
        "get_leads",
      ]);
      const result = ToolPolicyScanner.verifyManifest(pin, [
        "create_lead",
        "get_leads",
        "evil_backdoor",
      ]);
      expect(result.valid).toBe(false);
      expect(result.added).toContain("evil_backdoor");
    });

    it("detects manifest drift — removed tools", () => {
      const pin = ToolPolicyScanner.pinManifest("mcp-crm", [
        "create_lead",
        "get_leads",
        "delete_lead",
      ]);
      const result = ToolPolicyScanner.verifyManifest(pin, [
        "create_lead",
        "get_leads",
      ]);
      expect(result.valid).toBe(false);
      expect(result.removed).toContain("delete_lead");
    });

    it("validates unchanged manifest", () => {
      const tools = ["create_lead", "get_leads", "search_leads"];
      const pin = ToolPolicyScanner.pinManifest("mcp-crm", tools);
      const result = ToolPolicyScanner.verifyManifest(pin, tools);
      expect(result.valid).toBe(true);
    });

    it("detects unknown tools via scanner", async () => {
      const pin: ToolManifestPin = ToolPolicyScanner.pinManifest("mcp-crm", [
        "create_lead",
        "get_leads",
      ]);
      const pinScanner = new ToolPolicyScanner(policy, [pin]);

      const result = await pinScanner.scan("", {
        agentId: "support-agent",
        tools: [{ name: "evil_tool", serverId: "mcp-crm" }],
      });
      expect(result.violations.some((v) => v.type === "manifest_drift")).toBe(
        true,
      );
    });
  });

  describe("no tools", () => {
    it("allows when no tools in context", async () => {
      const result = await scanner.scan("Hello", {});
      expect(result.decision).toBe("allow");
    });
  });

  describe("performance", () => {
    it("checks in under 1ms", async () => {
      const result = await scanner.scan("", {
        agentId: "support-agent",
        tools: [{ name: "search_knowledge" }],
      });
      expect(result.durationMs).toBeLessThan(1);
    });
  });
});
