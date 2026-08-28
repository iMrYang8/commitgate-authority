import assert from "node:assert/strict";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(process.env.COMMITGATE_CANDIDATE_ROOT || "/proposal");
const ignored = new Set([".git", ".codex", "node_modules", "dist", "coverage"]);

async function walk(directory) {
  for (const name of (await readdir(directory)).sort()) {
    if (ignored.has(name)) continue;
    const absolute = path.join(directory, name);
    const stats = await lstat(absolute);
    assert.equal(stats.isSymbolicLink(), false, `symlink is not allowed: ${absolute}`);
    assert.equal(
      stats.isFile() || stats.isDirectory(),
      true,
      `special file is not allowed: ${absolute}`,
    );
    if (stats.isDirectory()) await walk(absolute);
  }
}

await walk(root);
assert.match(
  await readFile(path.join(root, "AGENTS.md"), "utf8"),
  /^# Platform-managed Agent instructions/m,
  "AGENTS.md must be the platform-generated instruction file",
);

try {
  JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

console.log("workspace-sanity: PASS");
