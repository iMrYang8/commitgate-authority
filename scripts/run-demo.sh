#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

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

if [[ -z "$MODEL_ID" || -z "$MODEL_API_KEY" ]]; then
  echo "MODEL_ID and MODEL_API_KEY are required in .env.local" >&2
  exit 1
fi

./scripts/demo-stack.sh foreground
