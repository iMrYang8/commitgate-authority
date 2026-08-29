import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const encodedRules = [
  "dGlrdG9r",
  "dGVjaGphbQ==",
  "dHJhY2tbIF8tXSox",
  "Y29kZWphbQ==",
  "cnJhbmtweXJhbWlk",
];

const rules = encodedRules.map((value) =>
  new RegExp(Buffer.from(value, "base64").toString("utf8"), "i"),
);

const tracked = execFileSync("git", ["ls-files", "-z"], {
  encoding: "utf8",
}).split("\0").filter(Boolean);

const findings = [];
for (const file of tracked) {
  const bytes = readFileSync(file);
  if (bytes.includes(0)) continue;
  const lines = bytes.toString("utf8").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (rules.some((rule) => rule.test(lines[index]))) {
      findings.push(`${file}:${index + 1}`);
    }
  }
}

if (findings.length > 0) {
  console.error("Public-copy vocabulary check failed:");
  for (const finding of findings) console.error(`- ${finding}`);
  process.exit(1);
}

console.log(`Public-copy vocabulary check passed (${tracked.length} tracked files).`);
