import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { TransitionEventLog } from "./transition-log.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("TransitionEventLog", () => {
  it("serializes concurrent immutable events into a verified digest chain", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-events-"));
    roots.push(root);
    const log = new TransitionEventLog(root);
    await Promise.all([
      log.append({ agentId: "agent", transitionId: "tx", type: "TRANSITION_PREPARED", payload: {} }),
      log.append({ agentId: "agent", transitionId: "tx", type: "PROPOSAL_SEALED", payload: { proposalId: "p1" } }),
      log.append({ agentId: "agent", transitionId: "tx", type: "EVIDENCE_RECORDED", payload: { digest: "e1" } }),
    ]);
    const events = await log.read("agent");
    expect(events.map((event) => event.sequence)).toEqual([1, 2, 3]);
    expect(events[1]?.previousDigest).toBe(events[0]?.digest);
  });

  it("detects an edited historical event", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-events-"));
    roots.push(root);
    const log = new TransitionEventLog(root);
    await log.append({ agentId: "agent", transitionId: "tx", type: "TRANSITION_PREPARED", payload: {} });
    const directory = path.join(root, "agent", "events");
    const [name] = await readdir(directory);
    const file = path.join(directory, name!);
    const value = JSON.parse(await readFile(file, "utf8"));
    value.payload = { tampered: true };
    await chmod(file, 0o600);
    await writeFile(file, JSON.stringify(value));
    await expect(log.read("agent")).rejects.toThrow("TRANSITION_LOG_DIGEST_INVALID");
  });

  it("requires repair expected-view and workspace-hash CAS", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-events-"));
    roots.push(root);
    const log = new TransitionEventLog(root);
    await expect(log.appendRepair({
      agentId: "agent",
      transitionId: "tx",
      action: "rollback",
      expectedViewId: "v1",
      actualViewId: "v2",
      expectedWorkspaceHash: "h1",
      actualWorkspaceHash: "h1",
    })).rejects.toThrow("REPAIR_CAS_MISMATCH");
  });
});
