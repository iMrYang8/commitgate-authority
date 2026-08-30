# README-only judge reproduction

This runbook is deliberately shorter than the project's release evaluator. It
tests whether a reviewer can start and understand the product from the public
README without relying on the development checkout, old reports, or private
knowledge.

## A. Public `main` with Ark

1. Clone `https://github.com/iMrYang8/commitgate-authority` anonymously into a
   new directory.
2. Follow only the three-step README quick start and configure the Ark values
   in `.env.local`.
3. Create a new Agent in the browser.
4. Send the documented normal task and require `COMMITTED`, `gN -> gN+1`.
5. Send the documented deployment task and require `QUARANTINED`, HEAD
   unchanged.

## B. Release archive without Git with OpenRouter

1. Verify the archive against its `.sha256` companion and extract it into a new
   directory.
2. Confirm that the directory has no `.git` and that
   `RELEASE_PROVENANCE.json` exists.
3. Copy `.env.local.example` to `.env.openrouter.local`, set
   `MODEL_PROVIDER=openrouter`, the OpenRouter base URL, model and key, then run:

   ```bash
   chmod 600 .env.openrouter.local
   npm ci
   COMMITGATE_ENV_FILE=.env.openrouter.local npm run demo
   # In a second terminal while the demo remains active:
   npm run demo:auth
   ```

4. Repeat the same browser COMMITTED and QUARANTINED tasks.

## Evidence record

For each run, record the delivery mode, Provider identity, source identity,
startup result, committed and quarantined Run IDs, base/next generation, HEAD
disposition, Agent Run duration, and SHA-256 of the two screenshots and
sanitized log excerpt. Never record a Provider key, auth token, raw environment
or host path.

This is a team-executed judge simulation, not an external audit. Its report is
written after the source freeze to
`eval/evidence/judge-reproduction-report.json`; a missing Provider credential
must remain `unverified`, not be replaced by a mock result.

## Three-run rehearsal gate

After both delivery modes work, perform three consecutive live rehearsals:

```text
demo:reset -> demo -> demo:auth -> create Agent -> COMMITTED
-> QUARANTINED -> HEAD unchanged -> demo:down
```

All three must succeed without editing code or the database. Record Agent Run
durations and require the observed p95 to remain below 45 seconds. If it does
not, shorten only the task payload to `result.txt` plus one small JSON file.
