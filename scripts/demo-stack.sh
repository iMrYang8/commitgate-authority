#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

state_dir="$repo_dir/.demo-state"
secret_dir="$state_dir/secrets"
port="${PUBLIC_PORT:-${PORT:-3000}}"
compose_project="${COMMITGATE_COMPOSE_PROJECT:-commitgate}"
stack_id="${COMMITGATE_STACK_ID:-${compose_project}-policy-v2}"

load_environment() {
  local require_credentials="${1:-true}"
  if [[ -f .env.local ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env.local
    set +a
  fi
  export MODEL_PROVIDER="${MODEL_PROVIDER:-ark}"
  export MODEL_ID="${MODEL_ID:-${ARK_MODEL:-}}"
  export MODEL_API_KEY="${MODEL_API_KEY:-${ARK_API_KEY:-}}"
  if [[ -z "${MODEL_BASE_URL:-}" ]]; then
    case "$MODEL_PROVIDER" in
      ark) MODEL_BASE_URL="${ARK_BASE_URL:-https://ark.cn-beijing.volces.com/api/v3}" ;;
      openrouter) MODEL_BASE_URL="https://openrouter.ai/api/v1" ;;
      *)
        if [[ "$require_credentials" == "true" ]]; then
          echo "MODEL_BASE_URL is required for Provider '$MODEL_PROVIDER'" >&2
          exit 1
        fi
        MODEL_BASE_URL="http://shutdown.invalid"
        ;;
    esac
  fi
  export MODEL_BASE_URL
  export MODEL_WIRE_API="${MODEL_WIRE_API:-responses}"
  export COMMITGATE_POLICY_PROFILE="${COMMITGATE_POLICY_PROFILE:-deployment-protected}"
  export PUBLIC_PORT="$port"
  export COMMITGATE_COMPOSE_PROJECT="$compose_project"
  export COMMITGATE_STACK_ID="$stack_id"
  # Evidence may be committed after the frozen product source. Bind runtime
  # proofs to the newest source-surface commit rather than an evidence-only
  # HEAD, and refuse to start while that source surface is dirty.
  COMMITGATE_SOURCE_REVISION="$(
    node --input-type=module -e '
      import("./scripts/evidence-utils.mjs").then(async ({ evidenceProvenance }) => {
        const source = await evidenceProvenance(process.cwd());
        if (!source.sourceRevision || !source.workingTreeCleanAtCapture) process.exit(1);
        process.stdout.write(source.sourceRevision);
      });
    '
  )"
  export COMMITGATE_SOURCE_REVISION
  if [[ "$require_credentials" == "true" && ( -z "$MODEL_ID" || -z "$MODEL_API_KEY" ) ]]; then
    echo "MODEL_ID and MODEL_API_KEY are required in .env.local" >&2
    exit 1
  fi
  # `docker compose down`, logs, and status must remain usable after a key was
  # revoked or .env.local was moved. Compose still parses MODEL_ID on those
  # control-plane commands, but it never needs the Provider credential value.
  if [[ "$require_credentials" != "true" && -z "$MODEL_ID" ]]; then
    export MODEL_ID="shutdown-only-placeholder"
  fi
  if [[ "$require_credentials" != "true" ]]; then
    # Control-plane commands consume the already-materialized runtime secret
    # file, never the Provider credential from the caller's environment.
    unset MODEL_API_KEY ARK_API_KEY
  fi
  if [[ "$require_credentials" == "true" && -z "${DOCKER_SOCKET_GID:-}" ]]; then
    # Docker Desktop/Colima can translate the mounted socket ownership inside
    # the VM, so the macOS host gid is not authoritative. Observe the gid from
    # the same container namespace that Runtime Broker will use.
    DOCKER_SOCKET_GID="$(
      docker run --rm \
        --volume /var/run/docker.sock:/var/run/docker.sock \
        --entrypoint stat \
        "${CONTAINER_RUNTIME_BASE_IMAGE:-node:22-bookworm-slim}" \
        -c '%g' /var/run/docker.sock 2>/dev/null || true
    )"
    export DOCKER_SOCKET_GID="${DOCKER_SOCKET_GID:-0}"
  fi
}

compose() {
  docker compose --project-name "$compose_project" "$@"
}

write_secrets() {
  mkdir -p "$secret_dir" "$state_dir/workspaces"
  chmod 700 "$state_dir" "$secret_dir"
  local relay_token auth_token broker_attestation_key
  relay_token="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(36).toString("base64url"))')"
  auth_token="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
  broker_attestation_key="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(48).toString("base64url"))')"
  printf '%s' "$MODEL_API_KEY" > "$secret_dir/model_api_key"
  # Docker Compose file-backed secrets preserve host ownership on native
  # Linux. Give each runtime UID an owner-only copy of the shared relay
  # capability instead of weakening the files to world/group-readable mode.
  printf '%s' "$relay_token" > "$secret_dir/relay_token_relay"
  printf '%s' "$relay_token" > "$secret_dir/relay_token_broker"
  printf '%s' "$relay_token" > "$secret_dir/relay_token_api"
  printf '%s' "$auth_token" > "$secret_dir/app_auth_token"
  printf '%s' "$broker_attestation_key" > "$secret_dir/broker_attestation_key"
  chmod 600 \
    "$secret_dir/model_api_key" \
    "$secret_dir/relay_token_relay" \
    "$secret_dir/relay_token_broker" \
    "$secret_dir/relay_token_api" \
    "$secret_dir/app_auth_token" \
    "$secret_dir/broker_attestation_key"
  # Root inside this one-shot helper changes only the ownership of the six
  # launcher-created secret files. The directory remains owned by the caller,
  # so cleanup does not require host privileges. Docker Desktop may virtualize
  # the chown; native Linux uses the exact service UIDs below.
  docker run --rm \
    --network none \
    --volume "$secret_dir:/secrets" \
    --entrypoint sh \
    busybox:1.36 \
    -ec 'chown 10002:10002 /secrets/model_api_key /secrets/relay_token_relay; chown 10001:10001 /secrets/relay_token_broker /secrets/broker_attestation_key; chown 1000:1000 /secrets/relay_token_api /secrets/app_auth_token; chmod 0600 /secrets/*'
}

remove_runtime_secrets() {
  # The files are required only while Relay/API containers are alive. Remove
  # them after shutdown so smoke-test cleanup leaves no plaintext credential
  # in the working tree; .env.local remains the user-controlled source.
  rm -f \
    "$secret_dir/model_api_key" \
    "$secret_dir/relay_token_relay" \
    "$secret_dir/relay_token_broker" \
    "$secret_dir/relay_token_api" \
    "$secret_dir/app_auth_token" \
    "$secret_dir/broker_attestation_key"
  rmdir "$secret_dir" >/dev/null 2>&1 || true
}

clear_demo_clipboard() {
  # Clear only when the clipboard still contains this stack's credential. The
  # helper deliberately leaves unrelated clipboard contents untouched.
  node scripts/demo-auth.mjs --clear >/dev/null 2>&1 || true
}

authenticated_system_status() {
  if [[ ! -s "$secret_dir/app_auth_token" ]]; then
    echo "Demo authentication secret is unavailable; start the stack first" >&2
    return 1
  fi
  DEMO_SYSTEM_URL="http://127.0.0.1:$port/api/system" \
    node - "$secret_dir/app_auth_token" <<'NODE'
const { readFileSync } = require("node:fs");
const token = readFileSync(process.argv[2], "utf8").trim();
fetch(process.env.DEMO_SYSTEM_URL, {
  headers: { authorization: `Bearer ${token}` },
}).then(async (response) => {
  const body = await response.text();
  if (!response.ok) {
    console.error(`system status request failed: HTTP ${response.status}`);
    process.exit(1);
  }
  process.stdout.write(`${body}\n`);
}).catch((error) => {
  console.error(`system status request failed: ${error.message}`);
  process.exit(1);
});
NODE
}

foreground_cleanup() {
  compose down --remove-orphans || true
  clear_demo_clipboard
  remove_runtime_secrets
}

legacy_down() {
  if [[ -f "$state_dir/server.pid" ]]; then
    kill "$(cat "$state_dir/server.pid")" >/dev/null 2>&1 || true
  fi
  if [[ -f "$state_dir/broker.pid" ]]; then
    kill "$(cat "$state_dir/broker.pid")" >/dev/null 2>&1 || true
  fi
  rm -f "$state_dir/server.pid" "$state_dir/broker.pid"
  docker rm --force commitgate-demo-model-relay >/dev/null 2>&1 || true
  docker network rm commitgate-demo-agent-relay >/dev/null 2>&1 || true
}

wait_ready() {
  local ready=false
  for _ in {1..240}; do
    if curl --fail --silent "http://127.0.0.1:$port/api/health" >/dev/null; then
      ready=true
      break
    fi
    sleep 0.5
  done
  if [[ "$ready" != true ]]; then
    compose ps >&2 || true
    compose logs --tail=160 >&2 || true
    return 1
  fi
}

start() {
  local mode="${1:-detached}"
  load_environment
  legacy_down
  # Freeze the exact Runtime/Verifier image and verifier policy inputs before
  # the Worker starts. `compose up` below is deliberately no-build so the
  # evidence-producing Broker cannot drift from these startup pins.
  compose build
  # Pin derivation runs before runtime secrets exist. Its launcher-local
  # synthetic attestation key validates config only and is never output;
  # write_secrets below creates the real per-start Broker/Worker key.
  eval "$(node --import tsx scripts/derive-worker-evidence-pins.ts --shell)"
  write_secrets
  # Candidate/export exchange state is never authoritative. Recreate this
  # volume on every start so a legacy unbounded local volume cannot silently
  # bypass the current tmpfs byte/inode contract; authority/control persist.
  compose down --remove-orphans >/dev/null 2>&1 || true
  docker volume rm "${stack_id}-exchange" >/dev/null 2>&1 || true
  # Secrets are rotated on every start. Force recreation so long-lived local
  # containers never retain the previous auth or relay capability in memory.
  compose up --detach --no-build --remove-orphans --force-recreate
  wait_ready
  PATH="/opt/homebrew/bin:$PATH" npm run demo:preflight

  DEMO_BASE_URL="http://127.0.0.1:$port" \
    APP_AUTH_TOKEN_FILE="$secret_dir/app_auth_token" \
    node scripts/demo-seed.mjs

  echo "CommitGate Authority V2 ready: http://127.0.0.1:$port"
  echo "Worker authority: transition-worker"
  echo "Runtime authority: runtime-broker"
  echo "Logs: npm run demo:logs"
  echo "Stop: npm run demo:down"
  if [[ "$mode" == "foreground" ]]; then
    trap foreground_cleanup EXIT INT TERM
    compose logs --follow api transition-worker runtime-broker model-relay
  fi
}

case "${1:-status}" in
  start) start ;;
  foreground) start foreground ;;
  status)
    load_environment false
    compose ps
    authenticated_system_status
    ;;
  logs)
    load_environment false
    compose logs --tail=200 api transition-worker runtime-broker model-relay
    ;;
  down)
    load_environment false
    legacy_down
    compose down --remove-orphans
    clear_demo_clipboard
    remove_runtime_secrets
    echo "CommitGate demo stopped"
    ;;
  reset)
    load_environment false
    legacy_down
    compose down --volumes --remove-orphans
    clear_demo_clipboard
    remove_runtime_secrets
    echo "CommitGate demo state volumes reset; .env.local was preserved"
    ;;
  *) echo "Usage: $0 start|foreground|status|logs|down|reset" >&2; exit 2 ;;
esac
