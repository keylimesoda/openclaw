import { beforeEach, describe, expect, it, vi } from "vitest";
import { initTrustWindowCache } from "../../infra/exec-approvals.js";
import { ErrorCodes } from "../protocol/index.js";
import { execApprovalsHandlers } from "./exec-approvals.js";
import type { GatewayClient, GatewayRequestContext } from "./types.js";

type ResponseError = {
  code?: string;
  message?: string;
};

type HandlerCallResult = {
  ok: boolean;
  payload: unknown;
  error: ResponseError | undefined;
  warnSpy: ReturnType<typeof vi.fn>;
};

function createClient(params: { id: string; mode: string; connId: string }): GatewayClient {
  return {
    connId: params.connId,
    connect: {
      client: {
        id: params.id,
        mode: params.mode,
        version: "test",
        platform: "test",
      },
    } as GatewayClient["connect"],
  };
}

async function invokeHandler(params: {
  method: keyof typeof execApprovalsHandlers;
  payload: Record<string, unknown>;
  client: GatewayClient | null;
}): Promise<HandlerCallResult> {
  const warnSpy = vi.fn();
  let captured: { ok: boolean; payload: unknown; error: ResponseError | undefined } | undefined;
  const handler = execApprovalsHandlers[params.method];
  await handler({
    req: { id: "req-1", method: params.method, params: params.payload } as never,
    params: params.payload,
    client: params.client,
    isWebchatConnect: () => false,
    respond: (ok, payload, error) => {
      captured = {
        ok,
        payload,
        error: error as ResponseError | undefined,
      };
    },
    context: {
      logGateway: {
        warn: warnSpy,
      },
    } as unknown as GatewayRequestContext,
  });
  if (!captured) {
    throw new Error("handler did not respond");
  }
  return { ...captured, warnSpy };
}

describe("exec approvals trust handler", () => {
  beforeEach(() => {
    initTrustWindowCache();
  });

  it("rejects trust grants from non-CLI callers", async () => {
    const backendClient = createClient({
      id: "openclaw-control-ui",
      mode: "backend",
      connId: "conn-backend",
    });
    const response = await invokeHandler({
      method: "exec.approvals.trust",
      payload: { agentId: "main", minutes: 5, force: false },
      client: backendClient,
    });
    expect(response.ok).toBe(false);
    expect(response.error?.code).toBe(ErrorCodes.INVALID_REQUEST);
    expect(response.error?.message).toContain("interactive CLI caller");
    expect(response.warnSpy).toHaveBeenCalledTimes(1);
  });

  it("derives grantedBy from caller metadata and ignores caller-supplied grantedBy", async () => {
    const cliClient = createClient({ id: "cli", mode: "cli", connId: "conn-cli" });
    const trustResponse = await invokeHandler({
      method: "exec.approvals.trust",
      payload: {
        agentId: "main",
        minutes: 5,
        grantedBy: "spoofed-by-caller",
        force: false,
      },
      client: cliClient,
    });
    expect(trustResponse.ok).toBe(true);

    const statusResponse = await invokeHandler({
      method: "exec.approvals.trust.status",
      payload: { agentId: "main" },
      client: cliClient,
    });
    expect(statusResponse.ok).toBe(true);
    expect(
      (statusResponse.payload as { trustWindow?: { grantedBy?: string } }).trustWindow?.grantedBy,
    ).toBe("cli:cli:conn-cli");
  });
});
