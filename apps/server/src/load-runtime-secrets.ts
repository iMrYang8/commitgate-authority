import { readFile } from "node:fs/promises";

/** Load Docker/Kubernetes secret files before the strict config parser runs. */
export async function loadRuntimeSecretFiles(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  for (const [fileVariable, valueVariable] of [
    ["APP_AUTH_TOKEN_FILE", "APP_AUTH_TOKEN"],
    ["MODEL_RELAY_TOKEN_FILE", "MODEL_RELAY_TOKEN"],
    ["BROKER_ATTESTATION_KEY_FILE", "BROKER_ATTESTATION_KEY"],
  ] as const) {
    const file = environment[fileVariable]?.trim();
    if (!file) continue;
    if (environment[valueVariable]?.trim()) {
      throw new Error(`${valueVariable} and ${fileVariable} cannot both be set`);
    }
    environment[valueVariable] = (await readFile(file, "utf8")).trim();
  }
}
