import { describe, expect, it, vi } from "vitest";
import type { ExecApprovalsResolved, TrustWindow } from "../infra/exec-approvals.js";

const appendTrustAuditEntry = vi.fn(() => {
  throw new Error("disk-full");
});

vi.mock("../infra/trust-audit.js", () => ({
  appendTrustAuditEntry,
}));

vi.mock("../infra/exec-approvals.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../infra/exec-approvals.js")>();
  const approvals: ExecApprovalsResolved = {
    path: "/tmp/exec-approvals.json",
    socketPath: "/tmp/exec-approvals.sock",
    token: "token",
    defaults: {
      security: "full",
      ask: "off",
      askFallback: "full",
      autoAllowSkills: false,
    },
    agent: {
      security: "full",
      ask: "off",
      askFallback: "full",
      autoAllowSkills: false,
    },
    allowlist: [],
    file: {
      version: 1,
      socket: { path: "/tmp/exec-approvals.sock", token: "token" },
      defaults: {
        security: "full",
        ask: "off",
        askFallback: "full",
        autoAllowSkills: false,
      },
      agents: {},
    },
  };
  const now = Date.now();
  const trustWindow: TrustWindow = {
    status: "active",
    expiresAt: now + 60_000,
    grantedAt: now,
    security: "full",
    ask: "off",
  };
  return {
    ...mod,
    resolveExecApprovals: vi.fn(() => approvals),
    getTrustWindow: vi.fn(() => trustWindow),
    isTrustWindowActive: vi.fn(() => true),
  };
});

const { createExecTool } = await import("./bash-tools.exec.js");

describe("exec trust audit failures", () => {
  it("does not fail successful gateway exec when audit append throws", async () => {
    appendTrustAuditEntry.mockImplementation(() => {
      throw new Error("disk-full");
    });

    const tool = createExecTool({ host: "gateway", security: "full", ask: "off" });
    const result = await tool.execute("call-trust-audit", { command: "node -p 21+21" });
    const text = result.content.find((part) => part.type === "text")?.text ?? "";

    expect(result.details.status).toBe("completed");
    expect(text).toContain("42");
    expect(appendTrustAuditEntry).toHaveBeenCalled();
  });
});
