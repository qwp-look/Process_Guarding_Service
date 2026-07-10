#!/usr/bin/env bash
# Build and run the scheduler cron parser tests only.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin:$PATH"
GXX="${GXX:-/mingw64/bin/g++.exe}"

mkdir -p build
echo "[unit:sched] compiling tests/test_sched_cron.cpp ..."
"$GXX" -std=c++17 -Wall -Wextra -O2 -Iinclude -Imodules/sched \
    tests/test_sched_cron.cpp modules/sched/SchedCron.cpp \
    -o build/test_sched_cron.exe

echo "[unit:sched] running ..."
./build/test_sched_cron.exe
