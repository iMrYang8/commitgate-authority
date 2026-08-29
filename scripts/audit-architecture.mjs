#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const checkOnly = process.argv.includes("--check");
const drawioPath = path.join(root, "docs", "commitgate-architecture.drawio");
const svgPath = path.join(root, "docs", "commitgate-architecture.svg");
const submissionRoot = path.resolve(root, "..", "..", "04_演示与提交");
const submissionDrawioPath = path.join(
  submissionRoot,
  "CommitGate_No_Evidence_No_Effect_Architecture.drawio",
);
const submissionSvgPath = path.join(
  submissionRoot,
  "CommitGate_No_Evidence_No_Effect_Architecture.svg",
);

const [drawio, svg, submissionDrawio, submissionSvg] = await Promise.all([
  readFile(drawioPath),
  readFile(svgPath),
  readFile(submissionDrawioPath),
  readFile(submissionSvgPath),
]);
const drawioText = drawio.toString("utf8");
const svgText = svg.toString("utf8");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const drawioSha256 = digest(drawio);
const svgSha256 = digest(svg);
const ids = [...drawioText.matchAll(/<mxCell\b[^>]*\bid="([^"]+)"/g)].map(
  (match) => match[1],
);
const idSet = new Set(ids);
const edges = [...drawioText.matchAll(/<mxCell\b([^>]*)\bedge="1"([^>]*)>([\s\S]*?)<\/mxCell>/g)]
  .map((match) => `${match[1]} ${match[2]} ${match[3]}`);
const ref = (text, key) => new RegExp(`\\b${key}="([^"]+)"`).exec(text)?.[1] ?? null;
const embedded = /<metadata id="drawio-source" data-encoding="base64">([^<]+)<\/metadata>/.exec(
  svgText,
)?.[1];
let embeddedBytes = null;
try {
  embeddedBytes = embedded ? Buffer.from(embedded, "base64") : null;
} catch {
  embeddedBytes = null;
}

const checks = [
  {
    id: "native-drawio-xml",
    verified:
      drawioText.startsWith("<mxfile ") &&
      (drawioText.match(/<diagram\b/g) ?? []).length === 1 &&
      !drawioText.includes("<!--"),
  },
  { id: "unique-cell-ids", verified: ids.length > 2 && ids.length === idSet.size },
  {
    id: "valid-edge-references-and-geometry",
    verified:
      edges.length > 0 &&
      edges.every((edge) => {
        const source = ref(edge, "source");
        const target = ref(edge, "target");
        return source && target && idSet.has(source) && idSet.has(target) && /<mxGeometry\b/.test(edge);
      }),
  },
  {
    id: "svg-embeds-exact-editable-source",
    verified:
      svgText.includes(`data-drawio-sha256="${drawioSha256}"`) &&
      embeddedBytes !== null &&
      Buffer.compare(embeddedBytes, drawio) === 0,
  },
  {
    id: "submission-drawio-byte-identical",
    verified: Buffer.compare(submissionDrawio, drawio) === 0,
  },
  {
    id: "submission-svg-byte-identical",
    verified: Buffer.compare(submissionSvg, svg) === 0,
  },
  {
    id: "core-invariant-visible",
    verified:
      /No evidence, no effect/i.test(drawioText) &&
      /sealedProposalHash = verifierInputHash = promotionSourceHash = finalAuthoritativeHash/.test(
        drawioText,
      ) &&
      /Persistent world: unchanged/.test(drawioText),
  },
];
const status = checks.every((check) => check.verified) ? "verified" : "failed";
const report = {
  schemaVersion: 1,
  kind: "architecture-artifact-audit",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  artifacts: {
    drawio: { path: path.relative(root, drawioPath), sha256: drawioSha256 },
    svg: { path: path.relative(root, svgPath), sha256: svgSha256 },
    submissionDrawio: { path: submissionDrawioPath, sha256: digest(submissionDrawio) },
    submissionSvg: { path: submissionSvgPath, sha256: digest(submissionSvg) },
  },
  checks: checks.map((check) => ({
    id: check.id,
    status: check.verified ? "verified" : "failed",
  })),
  claimBoundary:
    "Checks XML structure, edge references, embedded editable source and byte-identical release copies; it does not constitute an external design review.",
};
if (!checkOnly) {
  const reportPath = path.join(root, "eval", "evidence", "architecture-report.json");
  await mkdir(path.dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
}
for (const check of report.checks) console.log(`${check.status.padEnd(10)} ${check.id}`);
console.log(`${status}: architecture artifact audit${checkOnly ? " (no report written)" : ""}`);
if (status !== "verified") process.exitCode = 1;
