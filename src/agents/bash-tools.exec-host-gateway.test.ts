import { describe, expect, it, vi } from "vitest";

vi.mock("@mariozechner/pi-ai", () => ({
  getOAuthApiKey: () => null,
  getOAuthProviders: () => [],
  loginOpenAICodex: () => undefined,
}));

import {
  collectBwrapCommandBins,
  shouldEnableBwrapSandbox,
} from "./bash-tools.exec-host-gateway.js";

describe("shouldEnableBwrapSandbox", () => {
  it("requires the linux platform guard", () => {
    expect(
      shouldEnableBwrapSandbox({
        matchedViaSafeBins: true,
        pty: false,
        nsSandboxMode: "bwrap",
        hostSecurity: "allowlist",
        analysisOk: true,
        allowlistSatisfied: true,
        platform: "darwin",
        bwrapPath: "/usr/bin/bwrap",
      }),
    ).toBe(false);

    expect(
      shouldEnableBwrapSandbox({
        matchedViaSafeBins: true,
        pty: false,
        nsSandboxMode: "bwrap",
        hostSecurity: "allowlist",
        analysisOk: true,
        allowlistSatisfied: true,
        platform: "linux",
        bwrapPath: "/usr/bin/bwrap",
      }),
    ).toBe(true);
  });

  it("skips bwrap when host security is full (trust-window bypass)", () => {
    expect(
      shouldEnableBwrapSandbox({
        matchedViaSafeBins: true,
        pty: false,
        nsSandboxMode: "bwrap",
        hostSecurity: "full",
        analysisOk: true,
        allowlistSatisfied: true,
        platform: "linux",
        bwrapPath: "/usr/bin/bwrap",
      }),
    ).toBe(false);
  });

  it("skips bwrap for PTY commands or when bwrap is unavailable", () => {
    expect(
      shouldEnableBwrapSandbox({
        matchedViaSafeBins: true,
        pty: true,
        nsSandboxMode: "bwrap",
        hostSecurity: "allowlist",
        analysisOk: true,
        allowlistSatisfied: true,
        platform: "linux",
        bwrapPath: "/usr/bin/bwrap",
      }),
    ).toBe(false);

    expect(
      shouldEnableBwrapSandbox({
        matchedViaSafeBins: true,
        pty: false,
        nsSandboxMode: "bwrap",
        hostSecurity: "allowlist",
        analysisOk: true,
        allowlistSatisfied: true,
        platform: "linux",
        bwrapPath: null,
      }),
    ).toBe(false);
  });
});

describe("collectBwrapCommandBins", () => {
  it("collects lower-cased executable names from resolved command segments", () => {
    const bins = collectBwrapCommandBins([
      {
        raw: "curl https://example.com",
        argv: ["curl", "https://example.com"],
        resolution: {
          rawExecutable: "curl",
          resolvedPath: "/usr/bin/curl",
          executableName: "curl",
        },
      },
      {
        raw: "JQ .",
        argv: ["jq", "."],
        resolution: {
          rawExecutable: "jq",
          resolvedPath: "/usr/bin/jq",
          executableName: "JQ",
        },
      },
      {
        raw: "echo hi",
        argv: ["echo", "hi"],
        resolution: null,
      },
    ]);

    expect(Array.from(bins)).toEqual(["curl", "jq"]);
  });
});
