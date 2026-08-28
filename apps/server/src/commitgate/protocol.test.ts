import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { buildManifest, patchHash } from "./manifest.js";
import { copyWorkspace } from "./file-ops.js";
import { defaultCommitGatePolicy } from "./policy.js";
import { PromotionPermitStore } from "./promotion-permit-store.js";
import {
  computeEvaluationContextHash,
  createEvidenceBundle,
  createStateViewRef,
  sha256Canonical,
} from "./protocol.js";
import { SealedProposalStore, runtimeTeardownDigest } from "./sealed-proposal-store.js";
import type { EvaluationContext, StateViewRef } from "./types.js";

const roots: string[] = [];
const execFileAsync = promisify(execFile);

async function makeWritable(root: string): Promise<void> {
  await chmod(root, 0o700);
  const entries = await readdir(root, { withFileTypes: true });
  await Promise.all(
    entries.map(async (entry) => {
      const item = path.join(root, entry.name);
      if (entry.isDirectory()) {
        await makeWritable(item);
      } else {
        await chmod(item, 0o600);
      }
    }),
  );
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => {
      await makeWritable(root).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }),
  );
});

const digest = (label: string): string => sha256Canonical({ label });

function view(generation = 1): StateViewRef {
  return createStateViewRef({
    schemaVersion: 1,
    agentId: "agent",
    headVersionId: `v${generation}`,
    generation,
    versionedHash: digest("versioned"),
    platformManagedHash: digest("platform"),
    liveStateHash: digest("live"),
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
  });
}

async function sealedFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-protocol-"));
  roots.push(root);
  const controlPath = path.join(root, "control", "agent");
  const candidatePath = path.join(controlPath, "candidates", "run");
  await mkdir(candidatePath, { recursive: true });
  await writeFile(path.join(candidatePath, "README.md"), "sealed bytes\n");
  const manifest = await buildManifest(candidatePath, defaultCommitGatePolicy);
  const store = new SealedProposalStore();
  const sealed = await store.seal({
    runId: "run",
    agentId: "agent",
    controlPath,
    candidatePath,
    baseViewId: view().viewId,
    policy: defaultCommitGatePolicy,
    changedPathsDigest: patchHash([]),
    runtimeTeardownDigest: runtimeTeardownDigest({ removed: true }),
    expectedCandidateHash: manifest.hash,
  });
  return { controlPath, candidatePath, store, sealed };
}

describe("sealed state protocol", () => {
  it("binds generation into StateViewId so equal bytes cannot replay across ABA", () => {
    const before = view(1);
    const { viewId: _oldViewId, ...beforeInput } = before;
    const afterAba = createStateViewRef({
      ...beforeInput,
      generation: 3,
      headVersionId: "v3",
    });
    expect(afterAba.liveStateHash).toBe(before.liveStateHash);
    expect(afterAba.viewId).not.toBe(before.viewId);
  });

  it("never re-reads the original candidate after sealing", async () => {
    const fixture = await sealedFixture();
    expect((await stat(fixture.sealed.payloadPath)).mode & 0o222).toBe(0);
    expect(
      (await stat(path.join(fixture.sealed.payloadPath, "README.md"))).mode & 0o222,
    ).toBe(0);
    await writeFile(path.join(fixture.candidatePath, "README.md"), "late mutation\n");
    const resolved = await fixture.store.resolve(
      fixture.controlPath,
      fixture.sealed.proposal.proposalId,
      defaultCommitGatePolicy,
    );
    expect(await readFile(path.join(resolved.payloadPath, "README.md"), "utf8")).toBe(
      "sealed bytes\n",
    );
    expect(resolved.proposal.artifactHash).toBe(fixture.sealed.proposal.artifactHash);
  });

  it("rejects a sealed proposal whose payload root regains write permission", async () => {
    const fixture = await sealedFixture();
    await chmod(fixture.sealed.payloadPath, 0o755);
    await expect(
      fixture.store.resolve(
        fixture.controlPath,
        fixture.sealed.proposal.proposalId,
        defaultCommitGatePolicy,
      ),
    ).rejects.toThrow(/ROOT_NOT_READONLY/);
  });

  it("prevents an Agent PID1-exit background late-write from changing the sealed proposal or promotion source", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-late-writer-"));
    roots.push(root);
    const controlPath = path.join(root, "control", "agent");
    const candidatePath = path.join(controlPath, "candidates", "late-run");
    const markerPath = path.join(root, "release-late-writer");
    const candidateFile = path.join(candidatePath, "README.md");
    await mkdir(candidatePath, { recursive: true });
    await writeFile(candidateFile, "sealed bytes\n");

    const detachedWriter = [
      "const fs=require('node:fs');",
      `const marker=${JSON.stringify(markerPath)};`,
      `const target=${JSON.stringify(candidateFile)};`,
      "const timer=setInterval(()=>{if(fs.existsSync(marker)){clearInterval(timer);fs.writeFileSync(target,'late mutation\\n');}},10);",
      "setTimeout(()=>{clearInterval(timer);process.exit(2)},5000).unref();",
    ].join("");
    const pid1 = [
      "const {spawn}=require('node:child_process');",
      `const child=spawn(process.execPath,['-e',${JSON.stringify(detachedWriter)}],{detached:true,stdio:'ignore'});`,
      "child.unref();",
    ].join("");
    await execFileAsync(process.execPath, ["-e", pid1]);

    const manifest = await buildManifest(candidatePath, defaultCommitGatePolicy);
    const store = new SealedProposalStore();
    const sealed = await store.seal({
      runId: "late-run",
      agentId: "agent",
      controlPath,
      candidatePath,
      baseViewId: view().viewId,
      policy: defaultCommitGatePolicy,
      changedPathsDigest: patchHash([]),
      runtimeTeardownDigest: runtimeTeardownDigest({
        containerExited: true,
        containerRemoved: true,
        mountsReleased: true,
      }),
      expectedCandidateHash: manifest.hash,
    });

    await writeFile(markerPath, "go\n");
    for (let attempt = 0; attempt < 200; attempt += 1) {
      if ((await readFile(candidateFile, "utf8")) === "late mutation\n") break;
      await delay(10);
    }
    expect(await readFile(candidateFile, "utf8")).toBe("late mutation\n");

    const promotionSource = await store.resolve(
      controlPath,
      sealed.proposal.proposalId,
      defaultCommitGatePolicy,
    );
    const promoted = path.join(root, "promoted-from-sealed");
    await copyWorkspace(
      promotionSource.payloadPath,
      promoted,
      defaultCommitGatePolicy,
      { include: new Set(["versioned", "platformManaged"]) },
    );
    expect(await readFile(path.join(promotionSource.payloadPath, "README.md"), "utf8")).toBe(
      "sealed bytes\n",
    );
    expect(await readFile(path.join(promoted, "README.md"), "utf8")).toBe(
      "sealed bytes\n",
    );
  });

  it("durably rejects replay of a claimed promotion permit", async () => {
    const fixture = await sealedFixture();
    const baseView = view();
    const contextHash = digest("evaluation-context");
    const evidence = createEvidenceBundle({
      proposalId: fixture.sealed.proposal.proposalId,
      evaluationContextHash: contextHash,
      verifierInputHash: fixture.sealed.proposal.manifestHash,
      checkResultsHash: digest("checks"),
      coverage: "complete",
      requiredChecksPassed: true,
      issuedAt: new Date(0).toISOString(),
    });
    const permits = new PromotionPermitStore(() => new Date(1));
    const permit = await permits.issue({
      runId: "run",
      agentId: "agent",
      controlPath: fixture.controlPath,
      proposal: fixture.sealed.proposal,
      baseView,
      evaluationContextHash: contextHash,
      evidence,
      ttlMs: 60_000,
    });
    const claim = {
      agentId: "agent",
      controlPath: fixture.controlPath,
      permitId: permit.permitId,
      proposal: fixture.sealed.proposal,
      proposalPath: fixture.sealed.payloadPath,
      proposalManifest: fixture.sealed.manifest,
      baseView,
      evaluationContextHash: contextHash,
      evidenceDigest: evidence.digest,
    };
    const capability = await permits.claim(claim);
    await expect(permits.claim(claim)).rejects.toMatchObject({ code: "PERMIT_REPLAY" });
    expect((await capability.consume()).state).toBe("CONSUMED");
    await expect(capability.consume()).rejects.toMatchObject({ code: "PERMIT_REPLAY" });
    expect((await permits.markConsumed(fixture.controlPath, capability)).state).toBe(
      "CONSUMED",
    );
  });

  it("refuses to mint a permit for partial, failing, or wrong-input evidence", async () => {
    const fixture = await sealedFixture();
    const baseView = view();
    const contextHash = digest("evaluation-context");
    const permits = new PromotionPermitStore(() => new Date(1));
    const evidenceInput = {
      proposalId: fixture.sealed.proposal.proposalId,
      evaluationContextHash: contextHash,
      verifierInputHash: fixture.sealed.proposal.manifestHash,
      checkResultsHash: digest("checks"),
      coverage: "complete" as const,
      requiredChecksPassed: true,
      issuedAt: new Date(0).toISOString(),
    };
    const validEvidence = createEvidenceBundle(evidenceInput);
    const issue = (evidence: typeof validEvidence) =>
      permits.issue({
        runId: "run",
        agentId: "agent",
        controlPath: fixture.controlPath,
        proposal: fixture.sealed.proposal,
        baseView,
        evaluationContextHash: contextHash,
        evidence,
      });

    await expect(
      issue(createEvidenceBundle({ ...evidenceInput, coverage: "partial" })),
    ).rejects.toMatchObject({ code: "PERMIT_BINDING_MISMATCH" });
    await expect(
      issue(createEvidenceBundle({ ...evidenceInput, requiredChecksPassed: false })),
    ).rejects.toMatchObject({ code: "PERMIT_BINDING_MISMATCH" });
    await expect(
      issue(createEvidenceBundle({ ...evidenceInput, verifierInputHash: digest("other") })),
    ).rejects.toMatchObject({ code: "PERMIT_BINDING_MISMATCH" });
  });

  it("changes EvaluationContextHash when policy/check/verifier context drifts", () => {
    const context: EvaluationContext = {
      schemaVersion: 1,
      runId: "run",
      agentId: "agent",
      proposalId: "proposal",
      baseView: view(),
      manifestSchemaVersion: 2,
      policyHash: digest("policy"),
      checkBundleHash: digest("bundle"),
      checkSpecHash: digest("spec"),
      verifierImageDigest: digest("image"),
      verifierConfigHash: digest("config"),
      resourcePolicyHash: digest("resources"),
      sourceRevision: "revision",
    };
    const initial = computeEvaluationContextHash(context);
    expect(
      computeEvaluationContextHash({ ...context, checkBundleHash: digest("changed") }),
    ).not.toBe(initial);
    expect(
      computeEvaluationContextHash({ ...context, verifierImageDigest: digest("new-image") }),
    ).not.toBe(initial);
  });
});
