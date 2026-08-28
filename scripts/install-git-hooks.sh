#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

git config --local core.hooksPath .githooks
echo "Installed repository hooks from .githooks"
