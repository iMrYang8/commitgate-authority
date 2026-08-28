#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance } from "./evidence-utils.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const manualSecretReview = process.argv.includes("--manual-secret-review");
const input = process.argv.slice(2).find((argument) => !argument.startsWith("--")) ?? process.env.DEMO_VIDEO;
if (!input) throw new Error("Usage: npm run demo:verify-video -- /absolute/path/demo.mp4");
const videoPath = path.resolve(input);
const { stdout } = await execFileAsync("ffprobe", [
  "-v", "error",
  "-show_entries", "format=duration:stream=codec_type,width,height",
  "-of", "json",
  videoPath,
]);
const probe = JSON.parse(stdout);
const duration = Number(probe.format?.duration ?? 0);
const video = probe.streams?.find((stream) => stream.codec_type === "video");
const audio = probe.streams?.find((stream) => stream.codec_type === "audio");
const checks = [
  { id: "duration-165-185-seconds", status: duration >= 165 && duration <= 185 ? "verified" : "failed", detail: duration },
  { id: "video-stream", status: video ? "verified" : "failed", detail: video ?? null },
  { id: "audio-stream", status: audio ? "verified" : "failed", detail: audio ?? null },
  {
    id: "resolution-1280x720-minimum",
    status: Number(video?.width ?? 0) >= 1280 && Number(video?.height ?? 0) >= 720 ? "verified" : "failed",
    detail: video ? `${video.width}x${video.height}` : "missing",
  },
  {
    id: "manual-secret-visual-review",
    status: manualSecretReview ? "verified" : "unverified",
    detail: manualSecretReview
      ? "Operator explicitly confirmed the visual secret review."
      : "Rerun with --manual-secret-review only after a human confirms that no key, .env file, shell environment or unredacted receipt appears on screen.",
  },
];
const bytes = await readFile(videoPath);
const report = {
  schemaVersion: 1,
  kind: "three-minute-demo-video-verification",
  generatedAt: new Date().toISOString(),
  status: checks.some((check) => check.status === "failed")
    ? "failed"
    : checks.some((check) => check.status === "unverified")
      ? "unverified"
      : "verified",
  source: await evidenceProvenance(root),
  artifact: {
    path: videoPath,
    bytes: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  },
  checks,
};
const reportPath = path.join(root, "eval", "evidence", "demo-video-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
for (const check of checks) console.log(`${check.status.padEnd(10)} ${check.id}: ${JSON.stringify(check.detail)}`);
console.log(`video report: ${reportPath}`);
process.exitCode = report.status === "failed" ? 1 : report.status === "unverified" ? 2 : 0;
