#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "npm run poc is a compatibility alias for the sealed-protocol demo launcher."
exec "$repo_dir/scripts/run-demo.sh"
