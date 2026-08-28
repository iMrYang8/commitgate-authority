#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// Legacy command retained as a compatibility alias. Operator booleans and a
// manually selected video are not machine evidence; use the clean-clone
// browser evaluator, which reports unverified until mechanical artifacts exist.
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const result = spawnSync(
  process.execPath,
  [path.join(root, "scripts", "eval-browser-clean-clone.mjs"), ...process.argv.slice(2)],
  { cwd: root, env: process.env, stdio: "inherit" },
);
process.exit(result.status ?? 1);
