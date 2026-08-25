#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lab/chaos/infrastructure/deploy.sh
source "$here/infrastructure/deploy.sh"
