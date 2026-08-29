#!/usr/bin/env node

// Mounted read-only into the transition-worker evaluator container. It drives
// only typed RPC plus fixture writes inside the run-scoped exchange volume.
import { createHash } from "node:crypto";
import { access, chown, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const [
  { WorkerTransitionAuthorityClient },
  protocol,
  filesystem,
  logModule,
  receiptProofModule,
  workerPolicyModule,
] =
  await Promise.all([
    import("file:///app/apps/server/dist/transition-authority-client.js"),
    import("file:///app/apps/server/dist/commitgate/protocol.js"),
    import("file:///app/apps/server/dist/transition-worker/filesystem.js"),
    import("file:///app/apps/server/dist/transition-log.js"),
    import("file:///app/apps/server/dist/research/receipt-proof.js"),
    import("file:///app/apps/server/dist/worker-gate-policy.js"),
  ]);

const { sha256Canonical } = protocol;
const { buildWorkerManifest } = filesystem;
const { TransitionEventLog } = logModule;
const { receiptSigningKeyId, verifyAuthorityReceiptProof } = receiptProofModule;
const { WORKER_GATE_POLICY_HASH, WORKER_CHECK_SPEC_HASH } = workerPolicyModule;

const socketPath = process.env.TRANSITION_WORKER_SOCKET ?? "/run/commitgate/transition-worker.sock";
const workspaceRoot = process.env.TRANSITION_WORKER_WORKSPACE_ROOT ?? "/var/lib/commitgate/workspaces";
const controlRoot = process.env.TRANSITION_WORKER_CONTROL_ROOT ?? "/var/lib/commitgate/control";
const exchangeRoot = process.env.TRANSITION_WORKER_INBOX_ROOT ?? "/var/lib/commitgate/exchange";
const apiDataFile = process.env.API_DATA_FILE ?? "/app/data/launchpad.json";
const client = new WorkerTransitionAuthorityClient(socketPath, 10_000);
const agentId = process.env.RECOVERY_AGENT_ID ?? "recovery-agent";
const sourceRevision = process.env.COMMITGATE_SOURCE_REVISION ?? "";
if (!/^[a-f0-9]{40}$/.test(sourceRevision)) {
  throw new Error("RECOVERY_DRIVER_SOURCE_REVISION_INVALID");
}
const digest = (label) => createHash("sha256").update(label).digest("hex");
const exists = async (target) => access(target).then(() => true, () => false);

async function initializeAgent() {
  return client.initializeAgent({
    agentId,
    operationId: "initialize-recovery-agent",
    headVersionId: "initial-recovery-version",
    generation: 1,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
    name: "Recovery fixture",
    instructions: "# Recovery fixture\n",
  });
}

async function recordRuntimeTeardown(runId, scope, sessionEpoch) {
  return client.recordRuntimeTeardown({
    agentId,
    transitionId: runId,
    attestation: {
      schemaVersion: 1,
      runId,
      agentId,
      runLeaseId: `lease-${runId}`,
      sessionEpoch,
      scope,
      containerExited: true,
      containerRemoved: true,
      mountsReleased: true,
      source: "runtime-attestation",
    },
  });
}

async function commit(runId, initialProjection = null, receiptId = `receipt-${runId}`) {
  const baseProjection = initialProjection ?? await initializeAgent();
  const base = baseProjection.head;
  if (!base) throw new Error("RECOVERY_DRIVER_HEAD_MISSING");
  const candidateVolumeId = `candidate-${runId}`;
  await client.prepareRun({
    agentId,
    transitionId: runId,
    runId,
    runLeaseId: `lease-${runId}`,
    candidateVolumeId,
    expectedViewId: base.view.viewId,
    expectedWorkspaceHash: base.workspaceHash,
    baseGeneration: base.view.generation,
    sessionEpoch: base.view.sessionEpoch,
  });
  await mkdir(path.join(exchangeRoot, candidateVolumeId, "src"), { recursive: true });
  await writeFile(
    path.join(exchangeRoot, candidateVolumeId, "src", "business.txt"),
    `committed by ${runId}\n`,
    "utf8",
  );

  // The recovery evaluator does not launch a real Agent container for this
  // protocol-only transaction.  It must still drive the same durable teardown
  // fence as production before Worker-owned sealing is allowed.
  await recordRuntimeTeardown(runId, "AGENT", base.view.sessionEpoch);

  const proposalId = `proposal-${runId}`;
  const sealed = await client.sealProposal({
    agentId,
    transitionId: runId,
    proposalId,
    sourceVolumeId: candidateVolumeId,
    baseViewId: base.view.viewId,
    runtimeTeardownDigest: digest(`teardown:${runId}`),
  });
  const proposal = sealed.proposals[proposalId];
  if (!proposal) throw new Error("RECOVERY_DRIVER_PROPOSAL_MISSING");

  const evaluationContext = {
    schemaVersion: 1,
    runId,
    agentId,
    proposalId,
    baseView: base.view,
    manifestSchemaVersion: 2,
    policyHash: WORKER_GATE_POLICY_HASH,
    checkBundleHash: digest("check-bundle"),
    checkSpecHash: WORKER_CHECK_SPEC_HASH,
    verifierImageDigest: `sha256:${digest("verifier-image")}`,
    verifierConfigHash: digest("verifier-config"),
    resourcePolicyHash: digest("resource-policy"),
    sourceRevision,
  };
  const checks = [{
    id: "workspace-sanity",
    status: "PASS",
    exitCode: 0,
    durationMs: 1,
    outputHash: digest(`check-output:${runId}`),
    timedOut: false,
  }];
  const evaluationContextHash = sha256Canonical(evaluationContext);
  const checkResultsHash = sha256Canonical(checks);
  const evidenceDigest = sha256Canonical({
    schemaVersion: 1,
    proposalId,
    artifactHash: proposal.artifactHash,
    evaluationContextHash,
    checkResultsHash,
  });
  // Simulated verification is complete and no Agent/Verifier mount remains.
  // Persist the ALL-scope fact before evidence, permit, or promotion.
  await recordRuntimeTeardown(runId, "ALL", base.view.sessionEpoch);
  await client.recordEvidence({
    agentId,
    transitionId: runId,
    proposalId,
    evaluationContextHash,
    evidenceDigest,
    evaluationContext,
    verifierInputHash: proposal.artifactHash,
    checkResultsHash,
    coverage: "complete",
    requiredChecksPassed: true,
    checks,
  });

  const permitId = `permit-${runId}`;
  await client.issuePermit({
    agentId,
    transitionId: runId,
    permitId,
    proposalId,
    baseViewId: base.view.viewId,
    targetArtifactHash: proposal.artifactHash,
    evaluationContextHash,
    evidenceDigest,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  const versionId = `version-${runId}`;
  return client.applyPromotion({
    agentId,
    transitionId: runId,
    permitId,
    proposalId,
    expectedViewId: base.view.viewId,
    expectedWorkspaceHash: base.workspaceHash,
    versionId,
    receiptId,
  });
}

async function seedApiProjectionGap(runId) {
  const initial = await initializeAgent();
  const base = initial.head;
  const initialVersion = initial.versions[0];
  if (!base || !initialVersion) throw new Error("API_PROJECTION_SEED_BASE_MISSING");
  const committed = await commit(runId, initial, runId);
  const final = committed.head;
  if (!final) throw new Error("API_PROJECTION_SEED_FINAL_MISSING");
  const timestamp = "2026-08-29T00:00:00.000Z";
  const runLeaseId = `lease-${runId}`;
  const database = {
    version: 3,
    agents: [{
      id: agentId,
      name: "API projection recovery fixture",
      description: "",
      instructions: "",
      status: "busy",
      workspacePath: `/logical/${agentId}`,
      workspaceRef: { authority: "transition-worker", agentId },
      codexThreadId: "pre-crash-thread",
      sessionEpoch: base.view.sessionEpoch,
      needsReconciliation: false,
      headVersionId: base.view.headVersionId,
      stateGeneration: base.view.generation,
      currentViewId: base.view.viewId,
      currentVersionedHash: base.view.versionedHash,
      currentPlatformManagedHash: base.view.platformManagedHash,
      currentLiveStateHash: base.view.liveStateHash,
      agentConfigVersion: base.view.agentConfigVersion,
      policyVersion: base.view.policyVersion,
      activeRunLeaseId: runLeaseId,
      recoveryRequired: false,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    }],
    runs: [{
      id: runId,
      agentId,
      status: "running",
      prompt: "apply the API projection recovery fixture",
      output: null,
      error: null,
      usage: null,
      commitGate: null,
      legacyReceipt: null,
      transactionStatus: "EXECUTING",
      runLeaseId,
      submittedViewId: base.view.viewId,
      baseViewId: base.view.viewId,
      proposalId: null,
      evaluationContextHash: null,
      permitId: null,
      retryOfRunId: null,
      staleCallback: false,
      provider: null,
      startedAt: timestamp,
      completedAt: null,
      createdAt: timestamp,
    }],
    messages: [
      {
        id: `input-${runId}`,
        agentId,
        runId,
        role: "user",
        content: "apply the API projection recovery fixture",
        authority: "INPUT",
        viewId: base.view.viewId,
        proposalId: null,
        createdAt: timestamp,
      },
      {
        id: `assistant-${runId}`,
        agentId,
        runId,
        role: "assistant",
        content: "durable Worker fact awaiting API projection",
        authority: "PROVISIONAL",
        viewId: base.view.viewId,
        proposalId: `proposal-${runId}`,
        createdAt: timestamp,
      },
    ],
    versions: [{
      id: initialVersion.versionId,
      agentId,
      sequence: 1,
      parentVersionId: null,
      kind: "INITIAL",
      snapshotHash: initialVersion.workspaceHash,
      liveStateHash: initialVersion.workspaceHash,
      pathPolicyHash: "worker-authority",
      sourceRunId: null,
      sourceReceiptId: null,
      rollbackTargetVersionId: null,
      changedPaths: [],
      snapshotAvailable: true,
      generation: initialVersion.generation,
      viewId: initialVersion.viewId,
      transitionEventId: initialVersion.transitionId,
      createdAt: timestamp,
    }],
    snapshots: [{
      agentId,
      hash: initialVersion.snapshotId,
      sizeBytes: 0,
      state: "available",
      createdAt: timestamp,
    }],
  };
  await mkdir(path.dirname(apiDataFile), { recursive: true, mode: 0o700 });
  await writeFile(apiDataFile, `${JSON.stringify(database, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  // The evaluator API image runs as the standard node user (uid/gid 1000).
  await chown(path.dirname(apiDataFile), 1000, 1000);
  await chown(apiDataFile, 1000, 1000);
  return {
    agentId,
    runId,
    baseView: base.view,
    finalView: final.view,
    terminalReceipt: committed.terminalReceipts.find((receipt) => receipt.receiptId === runId),
    receiptProofPresent: Boolean(committed.receiptProofs[runId]),
  };
}

async function inspectApiProjection(runId) {
  const databaseText = await readFile(apiDataFile, "utf8");
  const database = JSON.parse(databaseText);
  const projection = await client.getProjection(agentId);
  const events = await new TransitionEventLog(path.join(controlRoot, "log")).read(agentId);
  const run = database.runs.find((item) => item.id === runId) ?? null;
  const agent = database.agents.find((item) => item.id === agentId) ?? null;
  const assistant = database.messages.find(
    (item) => item.runId === runId && item.role === "assistant",
  ) ?? null;
  const terminal = projection.terminalReceipts.find(
    (item) => item.receiptId === runId,
  ) ?? null;
  const proofEntry = projection.receiptProofs[runId] ?? null;
  const proofBundle = proofEntry
    ? await client.getReceiptProof(agentId, runId)
    : null;
  const terminalEvent = terminal
    ? events.find((event) => event.eventId === terminal.eventId) ?? null
    : null;
  const proofVerification = proofBundle
    ? verifyAuthorityReceiptProof(proofBundle)
    : { valid: false, reason: "proof missing" };
  return {
    databaseDigest: createHash("sha256").update(databaseText).digest("hex"),
    run: run && {
      id: run.id,
      status: run.status,
      transactionStatus: run.transactionStatus,
      output: run.output,
      decision: run.commitGate?.decision ?? null,
      baseGeneration: run.commitGate?.baseGeneration ?? null,
      nextGeneration: run.commitGate?.nextGeneration ?? null,
      baseViewId: run.commitGate?.baseViewId ?? null,
      nextViewId: run.commitGate?.nextViewId ?? null,
      effectInvariantSatisfied: run.commitGate?.effectProof?.invariantSatisfied ?? false,
    },
    agent: agent && {
      id: agent.id,
      status: agent.status,
      activeRunLeaseId: agent.activeRunLeaseId,
      headVersionId: agent.headVersionId,
      generation: agent.stateGeneration,
      viewId: agent.currentViewId,
      sessionEpoch: agent.sessionEpoch,
      codexThreadId: agent.codexThreadId,
      needsReconciliation: agent.needsReconciliation,
      liveStateHash: agent.currentLiveStateHash,
    },
    assistant: assistant && {
      authority: assistant.authority,
      viewId: assistant.viewId,
      proposalId: assistant.proposalId,
      content: assistant.content,
    },
    versions: database.versions
      .filter((item) => item.agentId === agentId)
      .map((item) => ({
        id: item.id,
        generation: item.generation,
        viewId: item.viewId,
        kind: item.kind,
      })),
    worker: {
      headViewId: projection.head?.view.viewId ?? null,
      headGeneration: projection.head?.view.generation ?? null,
      headWorkspaceHash: projection.head?.workspaceHash ?? null,
      terminalDecision: terminal?.decision ?? null,
      terminalEventId: terminal?.eventId ?? null,
      eventCount: events.length,
      lastEventDigest: events.at(-1)?.digest ?? null,
      projectionDigest: projection.digest,
      proofPresent: Boolean(proofEntry),
      proofValid: proofVerification.valid,
      proofReason: proofVerification.reason,
      proofTerminalEventBound:
        Boolean(proofEntry && terminalEvent) &&
        proofBundle?.schemaVersion === 3 &&
        Array.isArray(proofBundle.eventChain) &&
        proofBundle.proof.logSequence === terminalEvent.sequence &&
        proofBundle.proof.previousDigest === terminalEvent.previousDigest &&
        proofBundle.proof.eventDigest === terminalEvent.digest,
      proofDigest: proofBundle
        ? createHash("sha256").update(JSON.stringify(proofBundle)).digest("hex")
        : null,
    },
  };
}

async function rollback() {
  const initialized = await initializeAgent();
  const initialVersion = initialized.versions[0];
  if (!initialVersion) throw new Error("RECOVERY_DRIVER_INITIAL_VERSION_MISSING");
  const committed = await commit("commit-before-rollback", initialized);
  const base = committed.head;
  if (!base) throw new Error("RECOVERY_DRIVER_COMMITTED_HEAD_MISSING");
  const transitionId = "rollback-1";
  await client.prepare({
    agentId,
    transitionId,
    kind: "ROLLBACK",
    expectedViewId: base.view.viewId,
    expectedWorkspaceHash: base.workspaceHash,
    baseGeneration: base.view.generation,
  });
  const versionId = "version-rollback-1";
  return client.applyRollback({
    agentId,
    transitionId,
    rollbackPermitId: "rollback-permit-1",
    targetSnapshotId: initialVersion.snapshotId,
    targetVersionId: initialVersion.versionId,
    expectedViewId: base.view.viewId,
    expectedWorkspaceHash: base.workspaceHash,
    versionId,
    receiptId: "receipt-rollback-1",
  });
}

async function inspect(agent, transitionId) {
  const projection = await client.getProjection(agent);
  const manifest = await buildWorkerManifest(path.join(workspaceRoot, agent));
  const events = await new TransitionEventLog(path.join(controlRoot, "log")).read(agent);
  const transition = projection.transitions[transitionId] ?? null;
  const proposalId = transition?.proposalId ?? null;
  const permitId = transition?.permitId ?? null;
  const terminalReceipt = projection.terminalReceipts.find(
    (receipt) => receipt.transitionId === transitionId,
  ) ?? null;
  const compactProof = terminalReceipt
    ? projection.receiptProofs[terminalReceipt.receiptId] ?? null
    : null;
  const proofBundle = terminalReceipt && compactProof
    ? await client.getReceiptProof(agent, terminalReceipt.receiptId)
    : null;
  const proofVerification = proofBundle
    ? verifyAuthorityReceiptProof(proofBundle)
    : { valid: false, reason: "proof missing" };
  let signingKeyAnchor = null;
  try {
    signingKeyAnchor = receiptSigningKeyId(
      await readFile(path.join(controlRoot, "signing", "ed25519-public.pem"), "utf8"),
    );
  } catch {}
  let marker = null;
  try {
    marker = JSON.parse(await readFile(path.join(controlRoot, "heads", `${agent}.json`), "utf8"));
  } catch {}
  return {
    projection,
    transition,
    proposal: proposalId ? projection.proposals[proposalId] ?? null : null,
    permit: permitId ? projection.permits[permitId] ?? null : null,
    terminalReceipt,
    terminalProofPresent: proofBundle !== null,
    terminalProof: {
      schemaVersion: proofBundle?.schemaVersion ?? null,
      valid: proofVerification.valid,
      reason: proofVerification.reason,
      sourceRevision: proofBundle?.receipt.sourceRevision ?? null,
      expectedSourceRevision: sourceRevision,
      signingKeyId: proofBundle?.proof.signingKeyId ?? null,
      signingKeyAnchor,
      trustAnchorMatches:
        signingKeyAnchor !== null &&
        proofBundle?.proof.signingKeyId === signingKeyAnchor,
      fullEventChain:
        proofBundle?.schemaVersion === 3 &&
        Array.isArray(proofBundle.eventChain) &&
        proofBundle.eventChain.length > 0,
      terminalEventBound:
        proofBundle?.terminalEvent.eventId === terminalReceipt?.eventId &&
        proofBundle?.proof.eventDigest === proofBundle?.terminalEvent.digest,
    },
    workspaceManifestHash: manifest.hash,
    workspaceHashMatchesHead: manifest.hash === projection.head?.workspaceHash,
    eventChainVerified: true,
    events: events.map((event) => ({
      type: event.type,
      transitionId: event.transitionId,
      sequence: event.sequence,
      digest: event.digest,
    })),
    marker,
    markerMatchesProjection:
      marker?.viewId === projection.head?.view.viewId &&
      marker?.workspaceHash === projection.head?.workspaceHash &&
      marker?.projectionDigest === projection.digest,
    cleanup: {
      candidatePresent: await exists(path.join(exchangeRoot, `candidate-${transitionId}`)),
      stagingPresent: await exists(path.join(workspaceRoot, `.cg-stage-${agent}-${transitionId}`)),
      backupPresent: await exists(path.join(workspaceRoot, `.cg-backup-${agent}-${transitionId}`)),
      proposalPresent: proposalId
        ? await exists(path.join(controlRoot, "proposals", agent, proposalId))
        : false,
    },
  };
}

async function readSigningKeyAnchor() {
  const publicKeyPem = await readFile(
    path.join(controlRoot, "signing", "ed25519-public.pem"),
    "utf8",
  );
  return {
    keyId: receiptSigningKeyId(publicKeyPem),
    publicKeySha256: createHash("sha256").update(publicKeyPem).digest("hex"),
  };
}

const [action, argument] = process.argv.slice(2);
await client.initialize();
let result;
switch (action) {
  case "health":
    result = await client.initialize();
    break;
  case "run-commit":
    result = await commit(argument ?? "run-1");
    break;
  case "run-rollback":
    result = await rollback();
    break;
  case "inspect":
    result = await inspect(agentId, argument ?? "run-1");
    break;
  case "key-anchor":
    result = await readSigningKeyAnchor();
    break;
  case "seed-api-projection":
    result = await seedApiProjectionGap(argument ?? "api-projection-run");
    break;
  case "inspect-api-projection":
    result = await inspectApiProjection(argument ?? "api-projection-run");
    break;
  default:
    throw new Error(
      "Usage: recovery-docker-driver <health|key-anchor|run-commit|run-rollback|inspect|seed-api-projection|inspect-api-projection> [transition]",
    );
}
process.stdout.write(`${JSON.stringify(result)}\n`);
