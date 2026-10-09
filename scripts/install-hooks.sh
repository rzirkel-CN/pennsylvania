#!/usr/bin/env bash
# Configure this clone to use the repository's versioned quality gates.
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
git config core.hooksPath .githooks
printf 'Configured Git hooks from %s/.githooks\n' "$repo_root"
