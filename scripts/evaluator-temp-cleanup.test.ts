import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { removeEvaluatorTempTree } from "./evaluator-temp-cleanup.js";

async function fixtureRoot(name: string): Promise<{ parent: string; root: string }> {
  const parent = await mkdtemp(path.join(tmpdir(), "commitgate-cleanup-"));
  const evalDirectory = path.join(parent, "eval");
  await mkdir(evalDirectory);
  return { parent, root: path.join(evalDirectory, name) };
}

test("removes nested readonly trusted-check payload directories", async () => {
  const fixture = await fixtureRoot(".provider-ark-test");
  try {
    const payload = path.join(fixture.root, "workspaces", ".commitgate", "payloads", "digest");
    await mkdir(payload, { recursive: true });
    await writeFile(path.join(payload, "check.mjs"), "console.log('PASS');\n", { mode: 0o400 });
    await chmod(payload, 0o555);

    await removeEvaluatorTempTree(fixture.root);
    await assert.rejects(lstat(fixture.root), { code: "ENOENT" });
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test("does not traverse a symlink inside the evaluator temp tree", async () => {
  const fixture = await fixtureRoot(".browser-driver-test");
  const external = path.join(fixture.parent, "external");
  try {
    await mkdir(fixture.root);
    await mkdir(external);
    await writeFile(path.join(external, "marker.txt"), "outside\n");
    await chmod(external, 0o555);
    await symlink(external, path.join(fixture.root, "external-link"));
    await chmod(fixture.root, 0o555);

    await removeEvaluatorTempTree(fixture.root);

    assert.equal(await readFile(path.join(external, "marker.txt"), "utf8"), "outside\n");
    assert.equal((await lstat(external)).mode & 0o777, 0o555);
  } finally {
    await chmod(external, 0o755).catch(() => undefined);
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test("unlinks a symlink temp root without touching its target", async () => {
  const fixture = await fixtureRoot(".provider-ark-link-test");
  const external = path.join(fixture.parent, "external-root");
  try {
    await mkdir(external);
    await writeFile(path.join(external, "marker.txt"), "outside\n");
    await symlink(external, fixture.root);

    await removeEvaluatorTempTree(fixture.root);

    await assert.rejects(lstat(fixture.root), { code: "ENOENT" });
    assert.equal(await readFile(path.join(external, "marker.txt"), "utf8"), "outside\n");
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test("rejects roots outside the evaluator temp namespace", async () => {
  const parent = await mkdtemp(path.join(tmpdir(), "commitgate-cleanup-guard-"));
  try {
    await assert.rejects(
      removeEvaluatorTempTree(parent),
      /immediate child of eval/,
    );
    await lstat(parent);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
