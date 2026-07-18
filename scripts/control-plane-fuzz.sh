#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
control_dir="$(cd "$script_dir/../../updated_control" && pwd)"
iterations="${FUZZ_ITERATIONS:-20}"

cd "$control_dir"
docker compose down -v --remove-orphans
docker compose up -d --build control agent-1 agent-2 agent-3 agent-4 agent-5
docker compose --profile fuzz run --rm -e "FUZZ_ITERATIONS=$iterations" fuzzer

if command -v npm >/dev/null 2>&1; then
  npm install
  npx playwright install chromium
  npm run test:e2e
else
  echo "npm is required to run the Playwright control-plane checks" >&2
  exit 1
fi
