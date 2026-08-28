import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const candidateRoot = process.env.COMMITGATE_CANDIDATE_ROOT || "/proposal";
const result = await readFile(`${candidateRoot}/result.txt`, "utf8");
const protectedValue = await readFile(`${candidateRoot}/protected.txt`, "utf8");

assert.equal(result, "COMMITGATE_OK\n", "result.txt must exactly satisfy the trusted contract");
assert.equal(
  protectedValue,
  "TRUSTED_BASELINE\n",
  "protected.txt must retain the platform-owned baseline",
);
console.log("workspace-contract: PASS");
