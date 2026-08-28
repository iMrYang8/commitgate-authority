import { describe, expect, it } from "vitest";
import { parseWorkerCli } from "./cli.js";

describe("transition-worker repair CLI", () => {
  it("requires both repair CAS values", () => {
    expect(parseWorkerCli([
      "repair",
      "--agent", "agent-a",
      "--transition", "tx-a",
      "--action", "rollback",
      "--expected-view", "a".repeat(64),
      "--expected-workspace-hash", "b".repeat(64),
    ])).toMatchObject({ command: "repair", action: "rollback" });
    expect(() => parseWorkerCli([
      "repair", "--agent", "agent-a", "--transition", "tx-a", "--action", "rollback",
    ])).toThrow("--expected-view");
  });

  it("rejects force and raw path options", () => {
    expect(() => parseWorkerCli(["rebuild", "--agent", "agent-a", "--path", "/host"])).toThrow(
      "Unsupported CLI option",
    );
    expect(() => parseWorkerCli([
      "repair",
      "--agent", "agent-a",
      "--transition", "tx-a",
      "--action", "forward",
      "--expected-view", "a".repeat(64),
      "--expected-workspace-hash", "b".repeat(64),
      "--force", "true",
    ])).toThrow("Unsupported CLI option");
  });
});
