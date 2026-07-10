#!/usr/bin/env bash
# Build and run the PGS unit test suites.
# Reused by tools/verify_pgs.sh and CI (.github/workflows/build.yml) so the
# test path has exactly one implementation. Exits non-zero on any failure.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

bash ./tools/test_core_units.sh
bash ./tools/test_sched_cron.sh
