import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

describe("Authority V2 Compose RPC isolation", () => {
  it("uses distinct Worker and Broker socket volumes and grants API only the client mounts", async () => {
    const compose = await readFile(path.join(repositoryRoot, "docker-compose.yml"), "utf8");
    const workerService = compose.slice(
      compose.indexOf("\n  transition-worker:") + 1,
      compose.indexOf("\n  runtime-broker:"),
    );
    const brokerService = compose.slice(
      compose.indexOf("\n  runtime-broker:") + 1,
      compose.indexOf("\n  model-relay:"),
    );
    const apiService = compose.slice(
      compose.indexOf("\n  api:") + 1,
      compose.indexOf("\nnetworks:"),
    );

    expect(workerService).toContain(
      "transition-socket:/run/commitgate/transition",
    );
    expect(workerService).not.toContain("broker-socket:");
    expect(brokerService).toContain("broker-socket:/run/commitgate/broker");
    expect(brokerService).not.toContain("transition-socket:");
    expect(apiService).toContain(
      "transition-socket:/run/commitgate/transition:ro",
    );
    expect(apiService).toContain(
      "broker-socket:/run/commitgate/broker:ro",
    );
    expect(compose).not.toMatch(/^\s+sockets:\s*$/m);
  });

  it("shares the artifact-owner UID while keeping Worker and Broker socket groups disjoint", async () => {
    const compose = await readFile(path.join(repositoryRoot, "docker-compose.yml"), "utf8");
    expect(compose).toContain('user: "10001:20000"');
    expect(compose).toContain('group_add: ["20001"]');
    expect(compose).toContain('user: "10001:20002"');
    expect(compose).toContain('group_add: ["20000", "20001", "20002"]');
    expect(compose).toMatch(/runtime-broker:[\s\S]*?group_add:\n\s+- "20000"/);
  });

  it("kernel-bounds the single-active-run exchange by bytes and inodes", async () => {
    const compose = await readFile(path.join(repositoryRoot, "docker-compose.yml"), "utf8");
    const exchangeVolume = compose.slice(
      compose.indexOf("\n  exchange:") + 1,
      compose.indexOf("\n  sessions:"),
    );
    expect(exchangeVolume).toContain("type: tmpfs");
    expect(exchangeVolume).toContain("device: tmpfs");
    expect(exchangeVolume).toContain("COMMITGATE_EXCHANGE_BYTES");
    expect(exchangeVolume).toContain("COMMITGATE_EXCHANGE_INODES");
    expect(exchangeVolume).toContain("nr_inodes=");
    expect(exchangeVolume).toContain("mode=0770");
    expect(exchangeVolume).toContain("uid=10001");
    expect(exchangeVolume).toContain("gid=20000");
  });

  it("gates release evidence on the live exchange owner and shared artifact identity", async () => {
    const [topologyAudit, releaseAudit] = await Promise.all([
      readFile(path.join(repositoryRoot, "scripts/audit-topology.mjs"), "utf8"),
      readFile(path.join(repositoryRoot, "scripts/audit-release.mjs"), "utf8"),
    ]);
    for (const checkId of [
      "worker-broker-agent-artifact-identity-aligned",
      "exchange-volume-owner-aligned",
    ]) {
      expect(topologyAudit).toContain(`"${checkId}"`);
      expect(releaseAudit).toContain(`"${checkId}"`);
    }
  });

  it("mounts the Broker attestation key only into Worker and Broker", async () => {
    const compose = await readFile(path.join(repositoryRoot, "docker-compose.yml"), "utf8");
    const workerService = compose.slice(
      compose.indexOf("\n  transition-worker:") + 1,
      compose.indexOf("\n  runtime-broker:"),
    );
    const brokerService = compose.slice(
      compose.indexOf("\n  runtime-broker:") + 1,
      compose.indexOf("\n  model-relay:"),
    );
    const relayService = compose.slice(
      compose.indexOf("\n  model-relay:") + 1,
      compose.indexOf("\n  api:"),
    );
    const apiService = compose.slice(
      compose.indexOf("\n  api:") + 1,
      compose.indexOf("\nnetworks:"),
    );

    for (const service of [workerService, brokerService]) {
      expect(service).toContain(
        "BROKER_ATTESTATION_KEY_FILE: /run/secrets/broker_attestation_key",
      );
      expect(service).toMatch(/secrets:[\s\S]*?\n\s+- broker_attestation_key(?:\n|$)/);
    }
    for (const service of [apiService, relayService]) {
      expect(service).not.toContain("BROKER_ATTESTATION_KEY");
      expect(service).not.toContain("broker_attestation_key");
    }
    expect(compose).toContain(
      "broker_attestation_key:\n    file: ./.demo-state/secrets/broker_attestation_key",
    );
  });
});
