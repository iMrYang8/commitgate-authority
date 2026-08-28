#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

state_dir="$repo_dir/.demo-state"
secret_dir="$state_dir/secrets"
port="${PUBLIC_PORT:-${PORT:-3000}}"
compose_project="${COMMITGATE_COMPOSE_PROJECT:-commitgate}"
stack_id="${COMMITGATE_STACK_ID:-$compose_project}"

load_environment() {
  if [[ -f .env.local ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env.local
    set +a
  fi
  export MODEL_PROVIDER="${MODEL_PROVIDER:-ark}"
  export MODEL_ID="${MODEL_ID:-${ARK_MODEL:-}}"
  export MODEL_API_KEY="${MODEL_API_KEY:-${ARK_API_KEY:-}}"
  export MODEL_BASE_URL="${MODEL_BASE_URL:-${ARK_BASE_URL:-https://ark.cn-beijing.volces.com/api/v3}}"
  export MODEL_WIRE_API="${MODEL_WIRE_API:-responses}"
  export PUBLIC_PORT="$port"
  export COMMITGATE_COMPOSE_PROJECT="$compose_project"
  export COMMITGATE_STACK_ID="$stack_id"
  export COMMITGATE_SOURCE_REVISION="$(git rev-parse HEAD)"
  if [[ -z "$MODEL_ID" || -z "$MODEL_API_KEY" ]]; then
    echo "MODEL_ID and MODEL_API_KEY are required in .env.local" >&2
    exit 1
  fi
  if [[ -z "${DOCKER_SOCKET_GID:-}" ]]; then
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
  local relay_token auth_token
  relay_token="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(36).toString("base64url"))')"
  auth_token="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
  printf '%s' "$MODEL_API_KEY" > "$secret_dir/model_api_key"
  printf '%s' "$relay_token" > "$secret_dir/relay_token"
  printf '%s' "$auth_token" > "$secret_dir/app_auth_token"
  chmod 600 "$secret_dir/model_api_key" "$secret_dir/relay_token" "$secret_dir/app_auth_token"
}

remove_runtime_secrets() {
  # The files are required only while Relay/API containers are alive. Remove
  # them after shutdown so smoke-test cleanup leaves no plaintext credential
  # in the working tree; .env.local remains the user-controlled source.
  rm -f \
    "$secret_dir/model_api_key" \
    "$secret_dir/relay_token" \
    "$secret_dir/app_auth_token"
  rmdir "$secret_dir" >/dev/null 2>&1 || true
}

foreground_cleanup() {
  compose down --remove-orphans || true
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
  write_secrets
  # Secrets are rotated on every start. Force recreation so long-lived local
  # containers never retain the previous auth or relay capability in memory.
  compose up --detach --build --remove-orphans --force-recreate
  wait_ready
  PATH="/opt/homebrew/bin:$PATH" npm run demo:preflight

  local auth_token
  auth_token="$(cat "$secret_dir/app_auth_token")"
  DEMO_BASE_URL="http://127.0.0.1:$port" \
    APP_AUTH_TOKEN="$auth_token" \
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
    load_environment
    compose ps
    curl --fail --silent "http://127.0.0.1:$port/api/system" && printf '\n'
    ;;
  logs)
    load_environment
    compose logs --tail=200 api transition-worker runtime-broker model-relay
    ;;
  down)
    load_environment
    legacy_down
    compose down --remove-orphans
    remove_runtime_secrets
    echo "CommitGate demo stopped"
    ;;
  reset)
    load_environment
    legacy_down
    compose down --volumes --remove-orphans
    remove_runtime_secrets
    echo "CommitGate demo state volumes reset; .env.local was preserved"
    ;;
  *) echo "Usage: $0 start|foreground|status|logs|down|reset" >&2; exit 2 ;;
esac
