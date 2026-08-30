# Local compatibility launcher

`npm run poc` is retained only for users of the earlier command name. It is a
compatibility alias for the same sealed-protocol product launcher as:

```bash
npm run demo
```

It does **not** start the former lightweight local-process POC and it does not
define a second deployment profile. Both commands execute
`scripts/run-demo.sh`, which starts the unified root `docker-compose.yml` with:

```text
Browser/API
  -> Transition Worker (Authority/Control RW)
  -> Runtime Broker (Docker socket)
  -> Model Relay (Provider credential)
  -> isolated Agent/Verifier containers
```

## Use the canonical command

Requirements:

- Node.js 22+ and npm 10+;
- Docker with Compose and volume-subpath support;
- a Responses-compatible Provider endpoint, model ID, and key in the
  Git-ignored `.env.local` file.

```bash
cp .env.local.example .env.local
chmod 600 .env.local
# Edit MODEL_PROVIDER, MODEL_BASE_URL, MODEL_ID, MODEL_API_KEY.
npm run demo
```

After startup:

```bash
npm run demo:status
npm run demo:auth      # copies the temporary API token; does not print it
npm run demo:logs
npm run demo:down
```

`demo:down` and `demo:reset` remove generated Runtime secrets and clear the
clipboard only when it still contains this Demo's API token.

## Commands that are not release entrypoints

- `npm run poc`: compatibility spelling for `npm run demo`; use the canonical
  command in reproduction and release instructions.
- `npm start`: API-only development process. It does not start Worker, Broker,
  Relay, protected Runtime/Verifier containers, or the release permission
  topology.
- old split Relay/Worker Compose files: historical or evaluator scaffolds, not
  supported product launchers.
- `RUNTIME_PROVIDER=local-process`, direct Provider mode, rootless Podman, or a
  manually assembled partial stack: development/compatibility experiments only.
  They are not evidence for the Linux Docker release boundary.

The only release/Demo entry is `npm run demo`. Machine claims become verified
only when the expected reports are regenerated successfully from one clean,
frozen `SOURCE_REVISION`; this file and the launcher source are not runtime
evidence by themselves.
