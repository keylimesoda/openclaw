/**
 * Bubblewrap (bwrap) namespace sandbox for safeBins exec commands.
 *
 * Wraps commands in an unprivileged user namespace where only approved
 * binaries, system libraries, and the working directory are visible.
 * Trust windows bypass this entirely.
 *
 * Requirements:
 * - Linux (user namespaces must be enabled)
 * - bubblewrap (`bwrap`) installed (ships with Fedora/Ubuntu via Flatpak deps)
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// ── Types ──────────────────────────────────────────────────────────

export type BwrapSandboxMode = "none" | "bwrap";

export interface BwrapExtraBind {
  /** Source path on the host. */
  src: string;
  /** Destination path inside the sandbox (defaults to src). */
  dest?: string;
  /** Mount read-write (default: false = read-only). */
  writable?: boolean;
}

export interface BuildBwrapArgsParams {
  /** Set of approved safe-bin names (e.g. "curl", "jq"). */
  safeBins: ReadonlySet<string>;
  /** Directories to search for safe-bin binaries. */
  trustedSafeBinDirs: ReadonlySet<string>;
  /** Working directory (mounted read-write). */
  workdir: string;
  /** Optional workspace root; when provided, workdir must stay under it. */
  workspace?: string;
  /** Additional bind mounts. */
  extraBinds?: readonly BwrapExtraBind[];
  /** Extra shell binaries to mount (e.g. from getShellConfig). */
  extraShellBinaries?: readonly string[];
  /**
   * Actual command binaries used by the current command.
   * When omitted, network access stays enabled as a safe default.
   */
  commandBins?: ReadonlySet<string>;
}

// ── Constants ──────────────────────────────────────────────────────

/** Shell binaries that are always mounted (required for `sh -c`). */
const SHELL_BINARIES = ["sh", "bash"];

/** Commands that still need host networking inside this filesystem sandbox. */
const NETWORK_REQUIRED_BINS = new Set([
  "curl",
  "git",
  "pip3",
  "npm",
  "pnpm",
  "node",
  "python3",
  "ollama",
  "edge-tts",
  "yt-dlp",
  "gh",
  "mcporter",
  "systemctl",
]);

/** Known bubblewrap install locations, checked in order. */
const BWRAP_PATH_CANDIDATES = ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];

/** Shell + tool library roots mounted read-only for dynamic linking. */
const SYSTEM_LIB_PATHS = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/** System config paths mounted read-only (SSL, DNS, locale, etc). */
const SYSTEM_CONFIG_PATHS = [
  "/etc/ssl",
  "/etc/pki",
  "/etc/ca-certificates",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/nsswitch.conf",
  "/etc/localtime",
  "/etc/alternatives",
];

const SYNTHETIC_PASSWD_CONTENT = "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n";
const SYNTHETIC_GROUP_CONTENT = "nogroup:x:65534:\n";

const DENIED_BIND_PATHS = new Set([
  "/etc/shadow",
  "/etc/sudoers",
  "/proc",
  "/sys",
  path.join(os.homedir(), ".ssh"),
  path.join(os.homedir(), ".gnupg"),
]);

// ── Bwrap Detection (cached after first probe) ───────────────────

let _bwrapPath: string | null | undefined;
let _syntheticIdentityDir: string | undefined;

/**
 * Resolve the installed bwrap path (sync, cached).
 * Returns null when bubblewrap is unavailable.
 */
export function getBwrapPath(): string | null {
  if (_bwrapPath !== undefined) {
    return _bwrapPath;
  }
  for (const candidate of BWRAP_PATH_CANDIDATES) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      _bwrapPath = candidate;
      return candidate;
    } catch {
      // Try the next known location.
    }
  }
  _bwrapPath = null;
  return null;
}

/** Reset cached bwrap detection (for testing). */
export function resetBwrapCache(): void {
  _bwrapPath = undefined;
}

// ── Config Normalization ──────────────────────────────────────────

export function normalizeBwrapSandboxMode(value: unknown): BwrapSandboxMode {
  if (typeof value === "string" && value.trim().toLowerCase() === "bwrap") {
    return "bwrap";
  }
  return "none";
}

export function normalizeBwrapExtraBinds(value: unknown): BwrapExtraBind[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter(
      (entry): entry is Record<string, unknown> =>
        entry != null &&
        typeof entry === "object" &&
        typeof (entry as Record<string, unknown>).src === "string" &&
        ((entry as Record<string, unknown>).src as string).length > 0,
    )
    .map((entry) => ({
      src: entry.src as string,
      dest: typeof entry.dest === "string" ? entry.dest : undefined,
      writable: entry.writable === true,
    }));
}

// ── Core: Build bwrap Arguments ───────────────────────────────────

/**
 * Build the argv prefix for a bwrap-sandboxed command.
 *
 * This is filesystem-focused isolation only. Network access is still shared by
 * default unless `commandBins` proves the current command only needs local-only
 * tooling.
 *
 * Returns an array like:
 *   ["/usr/bin/bwrap", "--unshare-all", "--share-net", ...]
 *
 * The caller appends the separator and the actual command:
 *   [...buildBwrapArgs(params), "--", "sh", "-c", command]
 */
export function buildBwrapArgs(params: BuildBwrapArgsParams): string[] {
  const bwrapPath = getBwrapPath();
  if (!bwrapPath) {
    throw new Error("bubblewrap unavailable: bwrap not found in /usr/bin, /usr/local/bin, or /bin");
  }

  const args: string[] = [bwrapPath];
  const workdir = validateWorkdir(params.workdir, params.workspace);
  const mounted = new Set<string>();

  // Helper: add a bind mount, deduplicating by normalized destination.
  const addBind = (src: string, dest: string, writable: boolean) => {
    const normalizedDest = path.resolve(dest);
    if (mounted.has(normalizedDest)) {
      return;
    }
    mounted.add(normalizedDest);
    args.push(writable ? "--bind" : "--ro-bind", src, dest);
  };

  // ── Namespace isolation ──
  args.push("--unshare-all");
  if (shouldShareNetwork(params.commandBins)) {
    args.push("--share-net");
  }
  args.push("--die-with-parent", "--new-session");

  // TODO(security): add a seccomp-bpf profile via `bwrap --seccomp <fd>`.
  // Initial profile should keep common safe-bin workloads working while denying
  // obviously dangerous kernel attack surface that this PR does not yet cover,
  // including: ptrace, mount, umount2, bpf, kexec_load, kexec_file_load,
  // pivot_root, swapon, and swapoff.

  // ── Pseudo-filesystems ──
  args.push("--proc", "/proc");
  args.push("--dev", "/dev");
  // `/tmp` is intentionally a sandbox-local tmpfs, so host `/tmp` files are not
  // visible inside the namespace unless explicitly mounted via `extraBinds`.
  args.push("--tmpfs", "/tmp");

  // ── Shell binaries (always needed for sh -c execution) ──
  // Mount defaults plus any extra shells from getShellConfig().
  const allShells = new Set(SHELL_BINARIES);
  if (params.extraShellBinaries) {
    for (const shellBinary of params.extraShellBinaries) {
      allShells.add(shellBinary);
    }
  }
  for (const name of allShells) {
    const resolved = resolveInDirs(name, params.trustedSafeBinDirs);
    if (resolved) {
      addBind(resolved, resolved, false);
    }
  }

  // ── SafeBins binaries ──
  for (const name of params.safeBins) {
    const resolved = resolveInDirs(name, params.trustedSafeBinDirs);
    if (resolved) {
      addBind(resolved, resolved, false);
    }
  }

  // ── System libraries (dynamic linker, shared objects) ──
  // TODO(security): harden this further by mounting only the libraries required
  // by the actually-mounted executables (e.g. `ldd`-scoped mounts) instead of
  // exposing entire library roots.
  for (const libPath of SYSTEM_LIB_PATHS) {
    if (fs.existsSync(libPath)) {
      addBind(libPath, libPath, false);
    }
  }

  // ── System config (SSL certs, DNS, locale) ──
  for (const cfgPath of SYSTEM_CONFIG_PATHS) {
    if (fs.existsSync(cfgPath)) {
      addBind(cfgPath, cfgPath, false);
    }
  }

  const syntheticIdentityFiles = ensureSyntheticIdentityFiles();
  addBind(syntheticIdentityFiles.passwd, "/etc/passwd", false);
  addBind(syntheticIdentityFiles.group, "/etc/group", false);

  // ── Working directory (read-write) ──
  addBind(workdir, workdir, true);
  args.push("--chdir", workdir);

  // ── Extra user-specified binds ──
  if (params.extraBinds) {
    for (const bind of params.extraBinds) {
      const src = resolveBindPath(bind.src);
      const dest = bind.dest ? resolveBindPath(bind.dest) : src;
      assertAllowedExtraBind(src, dest);
      addBind(src, dest, bind.writable ?? false);
    }
  }

  return args;
}

// ── Helpers ───────────────────────────────────────────────────────

export function validateWorkdir(workdir: string, workspace?: string): string {
  const resolvedWorkdir = path.resolve(workdir);
  const segments = resolvedWorkdir.split(path.sep).filter(Boolean);

  if (
    resolvedWorkdir === path.parse(resolvedWorkdir).root ||
    resolvedWorkdir === "/home" ||
    resolvedWorkdir === "/root" ||
    segments.length <= 1
  ) {
    throw new Error(`Refusing to mount unsafe bwrap workdir: ${resolvedWorkdir}`);
  }

  if (workspace) {
    const resolvedWorkspace = path.resolve(workspace);
    if (!isPathWithin(resolvedWorkdir, resolvedWorkspace)) {
      throw new Error(
        `Refusing to mount bwrap workdir outside workspace: ${resolvedWorkdir} (workspace: ${resolvedWorkspace})`,
      );
    }
  }

  return resolvedWorkdir;
}

function shouldShareNetwork(commandBins?: ReadonlySet<string>): boolean {
  if (commandBins === undefined) {
    return true;
  }
  for (const bin of commandBins) {
    if (NETWORK_REQUIRED_BINS.has(bin.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/** Resolve a binary name in trusted directories. Returns absolute path or null. */
function resolveInDirs(name: string, dirs: ReadonlySet<string>): string | null {
  const trustedDirs = Array.from(dirs, (dir) => resolveTrustedDir(dir));
  for (const dir of dirs) {
    const candidate = path.join(dir, name);
    try {
      const stat = fs.statSync(candidate);
      if (!stat.isFile()) {
        continue;
      }
      const resolved = fs.realpathSync(candidate);
      if (!trustedDirs.some((trustedDir) => isPathWithin(resolved, trustedDir))) {
        continue;
      }
      return candidate;
    } catch {
      // Not found in this dir, broken symlink, or escaped trusted roots.
    }
  }
  return null;
}

function resolveTrustedDir(dir: string): string {
  try {
    return fs.realpathSync(dir);
  } catch {
    return path.resolve(dir);
  }
}

function ensureSyntheticIdentityFiles(): { passwd: string; group: string } {
  if (!_syntheticIdentityDir) {
    _syntheticIdentityDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-bwrap-identity-"));
  }
  const passwdPath = path.join(_syntheticIdentityDir, "passwd");
  const groupPath = path.join(_syntheticIdentityDir, "group");
  fs.writeFileSync(passwdPath, SYNTHETIC_PASSWD_CONTENT, { mode: 0o644 });
  fs.writeFileSync(groupPath, SYNTHETIC_GROUP_CONTENT, { mode: 0o644 });
  return { passwd: passwdPath, group: groupPath };
}

function resolveBindPath(input: string): string {
  return path.resolve(expandHomePrefix(input));
}

function expandHomePrefix(input: string): string {
  if (input === "~") {
    return os.homedir();
  }
  if (input.startsWith(`~${path.sep}`)) {
    return path.join(os.homedir(), input.slice(2));
  }
  return input;
}

function assertAllowedExtraBind(src: string, dest: string): void {
  if (isDeniedBindPath(src) || isDeniedBindPath(dest)) {
    console.warn(`Denied bwrap extra bind: ${src} -> ${dest}`);
    throw new Error(`Refusing denied bwrap extra bind: ${src} -> ${dest}`);
  }
}

function isDeniedBindPath(candidate: string): boolean {
  for (const deniedPath of DENIED_BIND_PATHS) {
    if (isPathWithin(candidate, deniedPath)) {
      return true;
    }
  }
  return false;
}

function isPathWithin(candidate: string, parent: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
