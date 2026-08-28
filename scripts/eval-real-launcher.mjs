#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const result = spawnSync(
  process.execPath,
  [path.join(root, "scripts", "eval-provider.mjs"), "--provider", "ark"],
  { cwd: root, env: process.env, stdio: "inherit" },
);
process.exit(result.status ?? 1);
