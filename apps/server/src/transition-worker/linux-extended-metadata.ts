import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
  WorkerExtendedMetadata,
  WorkerExtendedMetadataInspector,
  WorkerManifestOptions,
} from "./filesystem.js";

const execFileAsync = promisify(execFile);

const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_MAX_BUFFER_BYTES = 64 * 1024;
const DEFAULT_MAX_RECORDS = 1_024;
const ACL_STORAGE_XATTRS = new Set([
  "system.posix_acl_access",
  "system.posix_acl_default",
]);

export interface LinuxExtendedMetadataInspectorOptions {
  /** Absolute paths are fixed in the production image; overrides exist for tests. */
  getfattrPath?: string;
  getfaclPath?: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
  maxRecords?: number;
}

export type LinuxStrongWorkerManifestOverrides = Omit<
  WorkerManifestOptions,
  | "extendedMetadataInspector"
  | "requireExtendedMetadataInspection"
  | "requireSparseFileDetection"
  | "requireSingleFilesystem"
>;

function positiveBound(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`EXTENDED_METADATA_OPTION_INVALID:${name}`);
  }
  return value;
}

function absoluteToolPath(value: string, name: string): string {
  if (!value.startsWith("/") || value.includes("\0")) {
    throw new Error(`EXTENDED_METADATA_TOOL_PATH_INVALID:${name}`);
  }
  return value;
}

function normalizedLines(output: string, tool: "getfattr" | "getfacl"): string[] {
  if (output.includes("\0")) {
    throw new Error(`EXTENDED_METADATA_OUTPUT_MALFORMED:${tool}`);
  }
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

function parseXattrNames(output: string, maxRecords: number): string[] {
  const names = normalizedLines(output, "getfattr").map((line) => {
    const separator = line.indexOf("=");
    if (separator <= 0) {
      throw new Error("EXTENDED_METADATA_OUTPUT_MALFORMED:getfattr");
    }
    return line.slice(0, separator);
  }).filter((name) => !ACL_STORAGE_XATTRS.has(name));
  const unique = [...new Set(names)].sort();
  if (unique.length > maxRecords) {
    throw new Error("EXTENDED_METADATA_RECORD_LIMIT_EXCEEDED:getfattr");
  }
  return unique;
}

function parseNonTrivialAclEntries(output: string, maxRecords: number): string[] {
  const entries = normalizedLines(output, "getfacl");
  for (const entry of entries) {
    if (!/^(?:default:)?(?:user|group|mask|other):[^:]*:[rwx-]{3}$/.test(entry)) {
      throw new Error("EXTENDED_METADATA_OUTPUT_MALFORMED:getfacl");
    }
  }
  const nonTrivial = entries.filter(
    (entry) => !/^(?:user|group|other)::[rwx-]{3}$/.test(entry),
  );
  const unique = [...new Set(nonTrivial)].sort();
  if (unique.length > maxRecords) {
    throw new Error("EXTENDED_METADATA_RECORD_LIMIT_EXCEEDED:getfacl");
  }
  return unique;
}

function commandFailure(tool: "getfattr" | "getfacl", error: unknown): Error {
  const candidate = error as NodeJS.ErrnoException & {
    killed?: boolean;
    signal?: NodeJS.Signals | null;
  };
  if (candidate.code === "ENOENT") {
    return new Error(`EXTENDED_METADATA_TOOL_UNAVAILABLE:${tool}`);
  }
  if (
    candidate.killed === true ||
    candidate.signal !== undefined && candidate.signal !== null ||
    candidate.code === "ETIMEDOUT"
  ) {
    return new Error(`EXTENDED_METADATA_INSPECTION_TIMEOUT:${tool}`);
  }
  if (candidate.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
    return new Error(`EXTENDED_METADATA_OUTPUT_LIMIT_EXCEEDED:${tool}`);
  }
  return new Error(`EXTENDED_METADATA_INSPECTION_FAILED:${tool}`);
}

async function inspectCommand(
  tool: "getfattr" | "getfacl",
  executable: string,
  args: readonly string[],
  timeoutMs: number,
  maxBufferBytes: number,
): Promise<string> {
  try {
    const result = await execFileAsync(executable, [...args], {
      cwd: "/",
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: maxBufferBytes,
      windowsHide: true,
      // Do not inherit Provider credentials, PATH hooks, or language-specific
      // startup variables into the metadata inspection subprocesses.
      env: {
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin",
      },
    });
    return result.stdout;
  } catch (error) {
    throw commandFailure(tool, error);
  }
}

/**
 * Linux production inspector. It invokes fixed binaries directly (no shell),
 * bounds time/output, and returns names only. Attribute values and file paths
 * never enter the returned structure, receipt, or transition log.
 */
export function createLinuxExtendedMetadataInspector(
  options: LinuxExtendedMetadataInspectorOptions = {},
): WorkerExtendedMetadataInspector {
  if (process.platform !== "linux") {
    throw new Error("EXTENDED_METADATA_INSPECTION_UNAVAILABLE:platform");
  }
  const getfattrPath = absoluteToolPath(
    options.getfattrPath ?? "/usr/bin/getfattr",
    "getfattr",
  );
  const getfaclPath = absoluteToolPath(
    options.getfaclPath ?? "/usr/bin/getfacl",
    "getfacl",
  );
  const timeoutMs = positiveBound(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs");
  const maxBufferBytes = positiveBound(
    options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES,
    "maxBufferBytes",
  );
  const maxRecords = positiveBound(options.maxRecords ?? DEFAULT_MAX_RECORDS, "maxRecords");

  return async (absolutePath: string): Promise<WorkerExtendedMetadata> => {
    if (!absolutePath.startsWith("/") || absolutePath.includes("\0")) {
      throw new Error("EXTENDED_METADATA_PATH_INVALID");
    }
    const [xattrOutput, aclOutput] = await Promise.all([
      inspectCommand(
        "getfattr",
        getfattrPath,
        ["--no-dereference", "--absolute-names", "--dump", "--match=-", "--encoding=hex", "--", absolutePath],
        timeoutMs,
        maxBufferBytes,
      ),
      inspectCommand(
        "getfacl",
        getfaclPath,
        ["--absolute-names", "--omit-header", "--numeric", "--no-effective", "--", absolutePath],
        timeoutMs,
        maxBufferBytes,
      ),
    ]);
    return {
      xattrs: parseXattrNames(xattrOutput, maxRecords),
      aclEntries: parseNonTrivialAclEntries(aclOutput, maxRecords),
    };
  };
}

/** Options ready to pass directly to buildWorkerManifest/copyClosedTree. */
export function linuxStrongWorkerManifestOptions(
  overrides: LinuxStrongWorkerManifestOverrides = {},
): WorkerManifestOptions {
  return {
    ...overrides,
    requireExtendedMetadataInspection: true,
    requireSparseFileDetection: true,
    requireSingleFilesystem: true,
    extendedMetadataInspector: createLinuxExtendedMetadataInspector(),
  };
}
