#!/usr/bin/env node

if (process.argv.includes("--version")) {
  process.stdout.write("codex-cancellation-fixture 1.0.0\n");
  process.exit(0);
}

// The evaluator cancels this deliberately non-terminating Agent process via
// the production ContainerCodexRunner -> RuntimeBroker cancellation path.
// Ignore graceful termination so `docker rm --force` is mechanically needed.
process.on("SIGTERM", () => undefined);
process.stderr.write("agent-cancellation-fixture: ready\n");
setInterval(() => undefined, 1_000);
