#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

environment_file="${COMMITGATE_ENV_FILE:-.env.local}"
if [[ -f "$environment_file" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$environment_file"
  set +a
fi

export MODEL_PROVIDER="${MODEL_PROVIDER:-ark}"
export MODEL_ID="${MODEL_ID:-${ARK_MODEL:-}}"
export MODEL_API_KEY="${MODEL_API_KEY:-${ARK_API_KEY:-}}"
if [[ -z "${MODEL_BASE_URL:-}" ]]; then
  case "$MODEL_PROVIDER" in
    ark) MODEL_BASE_URL="${ARK_BASE_URL:-https://ark.cn-beijing.volces.com/api/v3}" ;;
    openrouter) MODEL_BASE_URL="https://openrouter.ai/api/v1" ;;
    *) echo "MODEL_BASE_URL is required for Provider '$MODEL_PROVIDER'" >&2; exit 1 ;;
  esac
fi
export MODEL_BASE_URL
export MODEL_WIRE_API="${MODEL_WIRE_API:-responses}"
export COMMITGATE_POLICY_PROFILE="${COMMITGATE_POLICY_PROFILE:-deployment-protected}"

if [[ -z "$MODEL_ID" || -z "$MODEL_API_KEY" ]]; then
  echo "MODEL_ID and MODEL_API_KEY are required in $environment_file" >&2
  exit 1
fi

./scripts/demo-stack.sh foreground
