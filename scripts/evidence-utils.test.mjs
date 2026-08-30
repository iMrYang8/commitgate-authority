import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createReleaseProvenanceManifest,
  evidenceProvenance,
  sourceTreeHash,
} from "./evidence-utils.mjs";

function git(root, ...args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "CommitGate provenance test",
      GIT_AUTHOR_EMAIL: "provenance-test@example.invalid",
      GIT_COMMITTER_NAME: "CommitGate provenance test",
      GIT_COMMITTER_EMAIL: "provenance-test@example.invalid",
    },
  }).trim();
}

async function put(root, relative, contents) {
  const absolute = path.join(root, relative);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, contents, "utf8");
}

test("source and evidence revisions remain distinct without report self-reference", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-evidence-provenance-"));
  try {
    git(root, "init", "--quiet", "--initial-branch=main");

    await put(root, "package.json", '{"name":"fixture","private":true}\n');
    await put(root, "eval/fixtures/attack/input.txt", "fixture-v1\n");
    git(root, "add", "package.json", "eval/fixtures/attack/input.txt");
    git(root, "commit", "--quiet", "-m", "freeze source H");
    const sourceH = git(root, "rev-parse", "HEAD");
    const atH = await evidenceProvenance(root);
    assert.equal(atH.sourceRevision, sourceH);
    assert.equal(atH.headRevision, sourceH);
    assert.equal(atH.workingTreeCleanAtCapture, true);

    // Generated evidence is outside the frozen source surface. Committing it
    // advances HEAD to E without changing either the source revision or hash.
    await put(root, "eval/evidence/result.json", '{"status":"verified"}\n');
    git(root, "add", "eval/evidence/result.json");
    git(root, "commit", "--quiet", "-m", "package evidence E");
    const evidenceE = git(root, "rev-parse", "HEAD");
    const atE = await evidenceProvenance(root);
    assert.notEqual(evidenceE, sourceH);
    assert.equal(atE.sourceRevision, sourceH);
    assert.equal(atE.headRevision, evidenceE);
    assert.equal(atE.sourceTreeHash, atH.sourceTreeHash);
    assert.equal(atE.sourceFileCount, atH.sourceFileCount);
    assert.equal(atE.workingTreeCleanAtCapture, true);

    // A real source edit advances the frozen source revision.
    await put(root, "package.json", '{"name":"fixture","private":true,"version":"2"}\n');
    git(root, "add", "package.json");
    git(root, "commit", "--quiet", "-m", "change source");
    const sourceS = git(root, "rev-parse", "HEAD");
    const atS = await evidenceProvenance(root);
    assert.equal(atS.sourceRevision, sourceS);
    assert.equal(atS.headRevision, sourceS);
    assert.notEqual(atS.sourceTreeHash, atE.sourceTreeHash);

    // Attack fixtures are executable evidence inputs, so they are source, not
    // generated reports. Even an uncommitted fixture edit changes the tree
    // hash and makes capture fail the clean-source gate.
    const fixtureHashBefore = await sourceTreeHash(root);
    await put(root, "eval/fixtures/attack/input.txt", "fixture-v2\n");
    const fixtureHashAfter = await sourceTreeHash(root);
    assert.notEqual(fixtureHashAfter.hash, fixtureHashBefore.hash);
    const dirtyFixture = await evidenceProvenance(root);
    assert.equal(dirtyFixture.sourceRevision, sourceS);
    assert.equal(dirtyFixture.headRevision, sourceS);
    assert.equal(dirtyFixture.workingTreeCleanAtCapture, false);

    git(root, "add", "eval/fixtures/attack/input.txt");
    git(root, "commit", "--quiet", "-m", "change source fixture");
    const fixtureF = git(root, "rev-parse", "HEAD");
    const atF = await evidenceProvenance(root);
    assert.equal(atF.sourceRevision, fixtureF);
    assert.equal(atF.headRevision, fixtureF);
    assert.equal(atF.sourceTreeHash, fixtureHashAfter.hash);
    assert.equal(atF.workingTreeCleanAtCapture, true);

    // A rename from the source surface into generated evidence still dirties
    // the source surface; both sides of porcelain's rename record are checked.
    git(root, "mv", "package.json", "eval/evidence/moved-package.json");
    const renamedOut = await evidenceProvenance(root);
    assert.equal(renamedOut.sourceRevision, fixtureF);
    assert.equal(renamedOut.workingTreeCleanAtCapture, false);
    git(root, "reset", "--hard", "--quiet", "HEAD");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a validated release manifest provides fail-closed provenance without .git", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-release-provenance-"));
  try {
    git(root, "init", "--quiet", "--initial-branch=main");
    await put(root, "package.json", '{"name":"archive-fixture","private":true}\n');
    await put(root, "apps/server/src/index.ts", "export const ready = true;\n");
    git(root, "add", ".");
    git(root, "commit", "--quiet", "-m", "freeze archive source");
    const manifest = await createReleaseProvenanceManifest(root);
    await put(root, "RELEASE_PROVENANCE.json", JSON.stringify(manifest, null, 2) + "\n");
    await rm(path.join(root, ".git"), { recursive: true, force: true });

    const release = await evidenceProvenance(root);
    assert.equal(release.sourceRevision, manifest.sourceRevision);
    assert.equal(release.headRevision, null);
    assert.equal(release.sourceTreeHash, manifest.sourceTreeHash);
    assert.equal(release.workingTreeCleanAtCapture, true);
    assert.equal(release.provenanceMode, "release-manifest");

    await put(root, "apps/server/src/index.ts", "export const ready = false;\n");
    await assert.rejects(
      evidenceProvenance(root),
      /SOURCE_PROVENANCE_MISMATCH:apps\/server\/src\/index\.ts/,
    );

    await put(root, "apps/server/src/index.ts", "export const ready = true;\n");
    await put(root, "apps/server/src/extra.ts", "export const extra = true;\n");
    await assert.rejects(evidenceProvenance(root), /SOURCE_PROVENANCE_MISMATCH:FILE_SET/);
    await rm(path.join(root, "apps/server/src/extra.ts"));
    await rm(path.join(root, "apps/server/src/index.ts"));
    await assert.rejects(evidenceProvenance(root), /SOURCE_PROVENANCE_MISMATCH:FILE_SET/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a source archive without Git or a release manifest is rejected", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-missing-provenance-"));
  try {
    await put(root, "package.json", '{"name":"unbound-archive","private":true}\n');
    await assert.rejects(evidenceProvenance(root), /SOURCE_PROVENANCE_UNAVAILABLE/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
