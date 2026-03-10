import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type BuildBwrapArgsParams,
  buildBwrapArgs,
  getBwrapPath,
  normalizeBwrapExtraBinds,
  normalizeBwrapSandboxMode,
  resetBwrapCache,
  validateWorkdir,
} from "./exec-bwrap-sandbox.js";

const BWRAP_PATHS = new Set(["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"]);

function createTempDir(tempDirs: string[], prefix: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function writeExecutable(dir: string, name: string) {
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, "#!/bin/sh\n", { mode: 0o755 });
  return filePath;
}

function expectBind(args: string[], flag: "--bind" | "--ro-bind", src: string, dest: string) {
  for (let i = 0; i < args.length - 2; i += 1) {
    if (args[i] === flag && args[i + 1] === src && args[i + 2] === dest) {
      return;
    }
  }
  throw new Error(`Missing bind ${flag} ${src} ${dest} in argv: ${args.join(" ")}`);
}

function countBindDest(args: string[], dest: string) {
  let count = 0;
  for (let i = 0; i < args.length - 2; i += 1) {
    if ((args[i] === "--bind" || args[i] === "--ro-bind") && args[i + 2] === dest) {
      count += 1;
    }
  }
  return count;
}

function mockBwrapPath(availablePath: string | null) {
  const originalAccessSync = fs.accessSync.bind(fs);
  return vi.spyOn(fs, "accessSync").mockImplementation((target, mode) => {
    const candidate = String(target);
    if (BWRAP_PATHS.has(candidate)) {
      if (candidate === availablePath) {
        return;
      }
      const err = new Error(
        `ENOENT: no such file or directory, access '${candidate}'`,
      ) as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    }
    return originalAccessSync(target, mode);
  });
}

// Integration pattern: keep bwrap execution itself in Linux-only integration tests
// that run against a real `bwrap` binary. These unit tests intentionally cover the
// deterministic pieces here: binary detection, mount planning, path validation, and
// sandbox argument construction.

afterEach(() => {
  resetBwrapCache();
  vi.restoreAllMocks();
});

describe("normalizeBwrapSandboxMode", () => {
  it("returns 'bwrap' for valid input", () => {
    expect(normalizeBwrapSandboxMode("bwrap")).toBe("bwrap");
    expect(normalizeBwrapSandboxMode("BWRAP")).toBe("bwrap");
    expect(normalizeBwrapSandboxMode(" bwrap ")).toBe("bwrap");
  });

  it("returns 'none' for invalid or missing input", () => {
    expect(normalizeBwrapSandboxMode("none")).toBe("none");
    expect(normalizeBwrapSandboxMode(undefined)).toBe("none");
    expect(normalizeBwrapSandboxMode(null)).toBe("none");
    expect(normalizeBwrapSandboxMode("")).toBe("none");
    expect(normalizeBwrapSandboxMode("docker")).toBe("none");
    expect(normalizeBwrapSandboxMode("chroot")).toBe("none");
  });
});

describe("normalizeBwrapExtraBinds", () => {
  it("normalizes valid entries", () => {
    const result = normalizeBwrapExtraBinds([
      { src: "/data", dest: "/mnt/data", writable: true },
      { src: "/opt/tools" },
    ]);
    expect(result).toEqual([
      { src: "/data", dest: "/mnt/data", writable: true },
      { src: "/opt/tools", dest: undefined, writable: false },
    ]);
  });

  it("skips invalid entries", () => {
    const result = normalizeBwrapExtraBinds([
      { src: "" },
      { src: 123 } as unknown as Record<string, unknown>,
      null as unknown as Record<string, unknown>,
      { src: "/valid" },
    ]);
    expect(result).toEqual([{ src: "/valid", dest: undefined, writable: false }]);
  });

  it("returns empty for null/undefined", () => {
    expect(normalizeBwrapExtraBinds(undefined)).toEqual([]);
    expect(normalizeBwrapExtraBinds(null)).toEqual([]);
  });
});

describe("getBwrapPath", () => {
  it("detects, caches, and resets the known bwrap path probe", () => {
    const accessSpy = mockBwrapPath("/usr/local/bin/bwrap");

    expect(getBwrapPath()).toBe("/usr/local/bin/bwrap");
    expect(getBwrapPath()).toBe("/usr/local/bin/bwrap");
    expect(accessSpy).toHaveBeenCalledTimes(2);
    expect(accessSpy).toHaveBeenNthCalledWith(1, "/usr/bin/bwrap", fs.constants.X_OK);
    expect(accessSpy).toHaveBeenNthCalledWith(2, "/usr/local/bin/bwrap", fs.constants.X_OK);

    resetBwrapCache();
    accessSpy.mockReset();
    mockBwrapPath("/bin/bwrap");

    expect(getBwrapPath()).toBe("/bin/bwrap");
  });

  it("returns null when bwrap is unavailable", () => {
    mockBwrapPath(null);
    expect(getBwrapPath()).toBeNull();
  });
});

describe("validateWorkdir", () => {
  it("rejects unsafe root-level workdirs", () => {
    expect(() => validateWorkdir("/")).toThrow(/unsafe bwrap workdir/i);
    expect(() => validateWorkdir("/home")).toThrow(/unsafe bwrap workdir/i);
    expect(() => validateWorkdir("/root")).toThrow(/unsafe bwrap workdir/i);
    expect(() => validateWorkdir("/tmp")).toThrow(/unsafe bwrap workdir/i);
  });

  it("rejects workdirs outside the provided workspace", () => {
    expect(() => validateWorkdir("/tmp/project/work", "/tmp/workspace")).toThrow(
      /outside workspace/i,
    );
  });

  it("accepts nested workdirs inside the workspace", () => {
    expect(validateWorkdir("/tmp/workspace/project", "/tmp/workspace")).toBe(
      "/tmp/workspace/project",
    );
  });
});

describe("buildBwrapArgs", () => {
  const tempDirs: string[] = [];
  let trustedBinDir = "";
  let defaultParams: BuildBwrapArgsParams;

  beforeEach(() => {
    mockBwrapPath("/usr/bin/bwrap");
    trustedBinDir = createTempDir(tempDirs, "bwrap-bin-");
    writeExecutable(trustedBinDir, "sh");
    writeExecutable(trustedBinDir, "bash");
    writeExecutable(trustedBinDir, "curl");
    writeExecutable(trustedBinDir, "jq");
    defaultParams = {
      safeBins: new Set(["curl", "jq"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: "/tmp/workspace/project",
    };
  });

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("starts with the detected bwrap binary", () => {
    const args = buildBwrapArgs(defaultParams);
    expect(args[0]).toBe("/usr/bin/bwrap");
  });

  it("throws when bwrap is unavailable", () => {
    resetBwrapCache();
    vi.restoreAllMocks();
    mockBwrapPath(null);
    expect(() => buildBwrapArgs(defaultParams)).toThrow(/bubblewrap unavailable/i);
  });

  it("mounts shell binary defaults when they resolve", () => {
    const shPath = path.join(trustedBinDir, "sh");
    const bashPath = path.join(trustedBinDir, "bash");
    const args = buildBwrapArgs(defaultParams);
    expectBind(args, "--ro-bind", shPath, shPath);
    expectBind(args, "--ro-bind", bashPath, bashPath);
  });

  it("skips unresolvable shell binaries", () => {
    const args = buildBwrapArgs({
      safeBins: new Set(["curl"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: "/tmp/workspace/project",
      extraShellBinaries: ["missing-shell"],
    });
    expect(args).not.toContain(path.join(trustedBinDir, "missing-shell"));
  });

  it("mounts safeBins binaries from trusted dirs", () => {
    const curlPath = path.join(trustedBinDir, "curl");
    const jqPath = path.join(trustedBinDir, "jq");
    const args = buildBwrapArgs(defaultParams);
    expectBind(args, "--ro-bind", curlPath, curlPath);
    expectBind(args, "--ro-bind", jqPath, jqPath);
  });

  it("does not mount binaries not in safeBins", () => {
    const rmPath = writeExecutable(trustedBinDir, "rm");
    const args = buildBwrapArgs({
      safeBins: new Set(["curl"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: "/tmp/workspace/project",
    });
    expect(args).not.toContain(rmPath);
  });

  it("rejects symlinked binaries that escape trusted directories", () => {
    const outsideDir = createTempDir(tempDirs, "bwrap-outside-");
    const outsideTool = writeExecutable(outsideDir, "outside-tool");
    const escapedLink = path.join(trustedBinDir, "escaped-tool");
    fs.symlinkSync(outsideTool, escapedLink);

    const args = buildBwrapArgs({
      safeBins: new Set(["escaped-tool"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: "/tmp/workspace/project",
    });

    expect(args).not.toContain(escapedLink);
    expect(args).not.toContain(outsideTool);
  });

  it("allows symlinked binaries whose real path stays inside trusted directories", () => {
    const realTool = writeExecutable(trustedBinDir, "real-tool");
    const linkedTool = path.join(trustedBinDir, "linked-tool");
    fs.symlinkSync(realTool, linkedTool);

    const args = buildBwrapArgs({
      safeBins: new Set(["linked-tool"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: "/tmp/workspace/project",
    });

    expectBind(args, "--ro-bind", linkedTool, linkedTool);
  });

  it("mounts system library paths read-only when present", () => {
    const args = buildBwrapArgs(defaultParams);
    if (fs.existsSync("/usr/lib")) {
      expectBind(args, "--ro-bind", "/usr/lib", "/usr/lib");
    }
  });

  it("binds synthetic passwd and group files instead of the host ones", () => {
    const args = buildBwrapArgs(defaultParams);
    const passwdIndex = args.findIndex(
      (arg, index) => arg === "--ro-bind" && args[index + 2] === "/etc/passwd",
    );
    const groupIndex = args.findIndex(
      (arg, index) => arg === "--ro-bind" && args[index + 2] === "/etc/group",
    );

    expect(passwdIndex).toBeGreaterThanOrEqual(0);
    expect(groupIndex).toBeGreaterThanOrEqual(0);
    expect(args[passwdIndex + 1]).not.toBe("/etc/passwd");
    expect(args[groupIndex + 1]).not.toBe("/etc/group");
  });

  it("mounts the working directory read-write and changes into it", () => {
    const args = buildBwrapArgs(defaultParams);
    expectBind(args, "--bind", "/tmp/workspace/project", "/tmp/workspace/project");
    const chdirIndex = args.indexOf("--chdir");
    expect(chdirIndex).toBeGreaterThanOrEqual(0);
    expect(args[chdirIndex + 1]).toBe("/tmp/workspace/project");
  });

  it("includes namespace isolation flags and starts a new session", () => {
    const args = buildBwrapArgs(defaultParams);
    expect(args).toContain("--unshare-all");
    expect(args).toContain("--share-net");
    const dieWithParentIndex = args.indexOf("--die-with-parent");
    expect(dieWithParentIndex).toBeGreaterThanOrEqual(0);
    expect(args[dieWithParentIndex + 1]).toBe("--new-session");
  });

  it("uses a local-only network profile when command bins do not require network", () => {
    const args = buildBwrapArgs({
      ...defaultParams,
      commandBins: new Set(["jq"]),
    });
    expect(args).not.toContain("--share-net");
  });

  it("keeps network access when any command bin requires it", () => {
    const args = buildBwrapArgs({
      ...defaultParams,
      commandBins: new Set(["jq", "curl"]),
    });
    expect(args).toContain("--share-net");
  });

  it("keeps network access when command bins are not provided", () => {
    const args = buildBwrapArgs(defaultParams);
    expect(args).toContain("--share-net");
  });

  it("includes pseudo-filesystems", () => {
    const args = buildBwrapArgs(defaultParams);
    expect(args).toContain("--proc");
    expect(args).toContain("/proc");
    expect(args).toContain("--dev");
    expect(args).toContain("/dev");
    expect(args).toContain("--tmpfs");
    expect(args).toContain("/tmp");
  });

  it("adds extra read-only and writable bind mounts", () => {
    const args = buildBwrapArgs({
      ...defaultParams,
      extraBinds: [
        { src: "/opt/data", writable: false },
        { src: "/opt/output", writable: true },
      ],
    });
    expectBind(args, "--ro-bind", "/opt/data", "/opt/data");
    expectBind(args, "--bind", "/opt/output", "/opt/output");
  });

  it("supports dest override in extra binds", () => {
    const args = buildBwrapArgs({
      ...defaultParams,
      extraBinds: [{ src: "/host/data", dest: "/sandbox/data" }],
    });
    expectBind(args, "--ro-bind", "/host/data", "/sandbox/data");
  });

  it("resolves relative workdir and extra bind sources to absolute paths", () => {
    const args = buildBwrapArgs({
      ...defaultParams,
      workdir: "relative/path/inside/workspace",
      extraBinds: [{ src: "relative/input", dest: "/sandbox/input" }],
    });
    const resolvedWorkdir = path.resolve("relative/path/inside/workspace");
    const resolvedSrc = path.resolve("relative/input");
    expectBind(args, "--bind", resolvedWorkdir, resolvedWorkdir);
    expectBind(args, "--ro-bind", resolvedSrc, "/sandbox/input");
  });

  it("does not duplicate mounts when multiple binds target the same destination", () => {
    const args = buildBwrapArgs({
      ...defaultParams,
      extraBinds: [
        { src: "/host/first", dest: "/sandbox/shared" },
        { src: "/host/second", dest: "/sandbox/shared" },
      ],
    });
    expect(countBindDest(args, "/sandbox/shared")).toBe(1);
  });

  it("does not duplicate shell binary mounts when a safeBin overlaps", () => {
    const shPath = path.join(trustedBinDir, "sh");
    const args = buildBwrapArgs({
      safeBins: new Set(["sh"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: "/tmp/workspace/project",
    });
    expect(countBindDest(args, shPath)).toBe(1);
  });

  it("handles spaces in workdir and rejects traversal-style bin names", () => {
    const outsideDir = createTempDir(tempDirs, "bwrap-escape-");
    const escapedTarget = writeExecutable(outsideDir, "evil");
    const spacedWorkdir = "/tmp/workspace/project with spaces";

    const args = buildBwrapArgs({
      safeBins: new Set(["../evil"]),
      trustedSafeBinDirs: new Set([trustedBinDir]),
      workdir: spacedWorkdir,
    });

    expectBind(args, "--bind", spacedWorkdir, spacedWorkdir);
    expect(args).not.toContain(escapedTarget);
  });

  it("warns and rejects denied extra bind paths", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    expect(() =>
      buildBwrapArgs({
        ...defaultParams,
        extraBinds: [{ src: "/etc/shadow" }],
      }),
    ).toThrow(/denied bwrap extra bind/i);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Denied bwrap extra bind"));
  });

  it("warns and rejects denied destination bind paths", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    expect(() =>
      buildBwrapArgs({
        ...defaultParams,
        extraBinds: [{ src: "/opt/data", dest: "/proc/self" }],
      }),
    ).toThrow(/denied bwrap extra bind/i);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("/proc/self"));
  });
});
