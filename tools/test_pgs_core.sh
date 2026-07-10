#!/usr/bin/env bash
# MSYS2 MinGW64 entry point kept for compatibility.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
bash ./tools/run_unit_tests.sh
