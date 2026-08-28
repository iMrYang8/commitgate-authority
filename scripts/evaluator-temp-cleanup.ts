import { chmod, lstat, readdir, rm } from "node:fs/promises";
import path from "node:path";

const evaluatorPrefixes = [".provider-", ".browser-driver-"];

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

function assertEvaluatorTempRoot(tempRoot: string): void {
  if (!path.isAbsolute(tempRoot)) {
    throw new Error("Evaluator temp root must be absolute");
  }
  if (path.basename(path.dirname(tempRoot)) !== "eval") {
    throw new Error("Evaluator temp root must be an immediate child of eval/");
  }
  if (!evaluatorPrefixes.some((prefix) => path.basename(tempRoot).startsWith(prefix))) {
    throw new Error("Evaluator temp root has an unexpected name");
  }
}

async function makeDirectoriesOwnerWritable(directory: string): Promise<void> {
  let stats;
  try {
    stats = await lstat(directory);
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }

  // lstat plus a directory-only recursion prevents an evaluator-created
  // symlink from making cleanup chmod or traverse a target outside tempRoot.
  if (stats.isSymbolicLink() || !stats.isDirectory()) return;

  await chmod(directory, (stats.mode & 0o777) | 0o700);
  for (const name of await readdir(directory)) {
    const child = path.join(directory, name);
    let childStats;
    try {
      childStats = await lstat(child);
    } catch (error) {
      if (isMissing(error)) continue;
      throw error;
    }
    if (childStats.isDirectory() && !childStats.isSymbolicLink()) {
      await makeDirectoriesOwnerWritable(child);
    }
  }
}

/**
 * Removes only an evaluator-owned temp tree. Trusted-check bundle payloads are
 * intentionally readonly, so their parent directories must first regain owner
 * write/search permission. Regular files are left untouched because unlinking
 * them depends on the parent directory, not the file mode.
 */
export async function removeEvaluatorTempTree(tempRoot: string): Promise<void> {
  assertEvaluatorTempRoot(tempRoot);

  let stats;
  try {
    stats = await lstat(tempRoot);
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }

  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    await rm(tempRoot, { force: true });
    return;
  }

  await makeDirectoriesOwnerWritable(tempRoot);
  await rm(tempRoot, { recursive: true, force: true });
}
