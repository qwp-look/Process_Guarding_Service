#!/usr/bin/env bash
# Build and run the scheduler cron parser tests only.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"
BUILD_DIR="${PGS_BUILD_DIR:-build}"

mkdir -p "$BUILD_DIR"
echo "[unit:sched] compiling tests/test_sched_cron.cpp ..."
"$GXX" -std=c++17 -Wall -Wextra -O2 -Iinclude -Imodules/sched \
    tests/test_sched_cron.cpp modules/sched/SchedCron.cpp \
    -o "$BUILD_DIR/test_sched_cron.exe"

echo "[unit:sched] running ..."
"$BUILD_DIR/test_sched_cron.exe"
