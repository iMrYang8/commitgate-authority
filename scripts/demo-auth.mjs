#!/usr/bin/env node
import { access, readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const tokenPath =
  process.env.COMMITGATE_DEMO_AUTH_TOKEN_FILE ??
  path.join(root, ".demo-state", "secrets", "app_auth_token");
const clearRequested = process.argv.includes("--clear");
const selfTest = process.argv.includes("--self-test");

function commandExists(command) {
  const probe = spawnSync(
    process.platform === "win32" ? "where" : "command",
    process.platform === "win32" ? [command] : ["-v", command],
    {
      encoding: "utf8",
      shell: process.platform !== "win32",
      stdio: ["ignore", "ignore", "ignore"],
    },
  );
  return probe.status === 0;
}

function chooseBackend() {
  if (process.platform === "darwin" && commandExists("pbcopy") && commandExists("pbpaste")) {
    return {
      name: "macOS pasteboard",
      write: ["pbcopy", []],
      read: ["pbpaste", []],
    };
  }
  if (process.platform === "win32" && commandExists("powershell.exe")) {
    return {
      name: "Windows clipboard",
      write: ["powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$input | Set-Clipboard"]],
      read: ["powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"]],
    };
  }
  if (commandExists("wl-copy") && commandExists("wl-paste")) {
    return {
      name: "Wayland clipboard",
      write: ["wl-copy", []],
      read: ["wl-paste", ["--no-newline"]],
    };
  }
  if (commandExists("xclip")) {
    return {
      name: "X11 xclip",
      write: ["xclip", ["-selection", "clipboard", "-in"]],
      read: ["xclip", ["-selection", "clipboard", "-out"]],
    };
  }
  if (commandExists("xsel")) {
    return {
      name: "X11 xsel",
      write: ["xsel", ["--clipboard", "--input"]],
      read: ["xsel", ["--clipboard", "--output"]],
    };
  }
  return null;
}

function writeClipboard(backend, value) {
  const [command, args] = backend.write;
  const result = spawnSync(command, args, {
    input: value,
    encoding: "utf8",
    stdio: ["pipe", "ignore", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`${backend.name} write failed`);
  }
}

function readClipboard(backend) {
  const [command, args] = backend.read;
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`${backend.name} read failed`);
  }
  return result.stdout;
}

if (selfTest) {
  const backend = chooseBackend();
  console.log(
    backend
      ? `verified: clipboard backend available (${backend.name}); no credential copied`
      : "unverified: install pbcopy/pbpaste, wl-clipboard, xclip, or xsel",
  );
  process.exit(backend ? 0 : 2);
}

const backend = chooseBackend();
if (!backend) {
  console.error(
    "No supported clipboard backend found. Install wl-clipboard, xclip, or xsel on Linux.",
  );
  process.exit(2);
}

try {
  await access(tokenPath);
} catch {
  if (clearRequested) {
    console.log("No active Demo credential was available to clear.");
    process.exit(0);
  }
  console.error("Demo is not running or its runtime authentication secret is unavailable.");
  process.exit(1);
}

const token = await readFile(tokenPath, "utf8");
if (!token) {
  console.error("The Demo authentication secret is empty.");
  process.exit(1);
}

if (clearRequested) {
  const current = readClipboard(backend);
  if (current === token) {
    writeClipboard(backend, "");
    console.log("Demo credential cleared from the clipboard.");
  } else {
    console.log("Clipboard was left unchanged because it no longer contains the Demo credential.");
  }
} else {
  writeClipboard(backend, token);
  console.log(`Demo credential copied using ${backend.name}; the credential value was not printed.`);
}
