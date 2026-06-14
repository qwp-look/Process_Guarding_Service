#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin"

# Lightweight runtime validation for the most failure-prone paths:
# - console run mode startup
# - token auth + token rotation persistence
# - protocol ping/list/get
# - atomic bless-start flow
# - persisted guard recovery after service restart

token="smoke-token"
rotated_token="smoke-token-rotated"
service_pid=""
service_job_pid=""
guard_pid=""
worker_path_win="$(cygpath -w "$repo_root/build/smoke_worker.exe")"
service_log="$repo_root/build/smoke_service.log"
service_err_log="$repo_root/build/smoke_service.err.log"
ps_exe="/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

process_exists() {
  local pid="$1"
  "$ps_exe" -NoProfile -Command "if (Get-Process -Id $pid -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >/dev/null 2>&1
}

force_stop_process() {
  local pid="$1"
  "$ps_exe" -NoProfile -Command "Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue" >/dev/null 2>&1 || true
}

start_service_process() {
  local token_value="${1:-}"
  if [[ -n "$token_value" ]]; then
    ./build/pgs_service.exe run --token "$token_value" >"$service_log" 2>"$service_err_log" &
  else
    ./build/pgs_service.exe run >"$service_log" 2>"$service_err_log" &
  fi

  service_job_pid=$!
  for _ in $(seq 1 20); do
    if [[ -r "/proc/$service_job_pid/winpid" ]]; then
      tr -d '\r\n' <"/proc/$service_job_pid/winpid"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

cleanup() {
  set +e

  if [[ -n "$guard_pid" ]]; then
    ./build/pgs_bless.exe intentional --pid "$guard_pid" --token "$token" >/dev/null 2>&1 || true
    force_stop_process "$guard_pid"
  fi

  if [[ -n "$service_pid" ]]; then
    force_stop_process "$service_pid"
  fi
  if [[ -n "$service_job_pid" ]]; then
    kill "$service_job_pid" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

echo "[Smoke] Starting console PGS..."
service_pid="$(start_service_process "$token" | tr -d '\r\n')"
if [[ ! "$service_pid" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to start service host process"
  exit 1
fi

ready=0
for _ in $(seq 1 40); do
  if ./build/pgs_bless.exe ping --token "$token" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done

if [[ "$ready" -ne 1 ]]; then
  echo "[Smoke] PGS did not become ready"
  exit 1
fi

echo "[Smoke] ping ok"
./build/pgs_bless.exe list --json --token "$token" >"$repo_root/build/smoke_list_initial.json"

echo "[Smoke] rotating token..."
./build/pgs_bless.exe token-set --old-token "$token" --new-token "$rotated_token" --token "$token" >/dev/null
token="$rotated_token"
./build/pgs_bless.exe ping --token "$token" >/dev/null

echo "[Smoke] bless-start smoke_worker..."
bless_output="$(
  ./build/pgs_bless.exe bless-start \
    --path "$worker_path_win" \
    --start-args "--sleep-ms 30000" \
    --max-restarts 1 \
    --hash auto \
    --token "$token"
)"
printf '%s\n' "$bless_output" >"$repo_root/build/smoke_bless_start.log"

guard_pid="$(printf '%s\n' "$bless_output" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "$guard_pid" ]]; then
  echo "[Smoke] failed to parse guard pid from bless-start output"
  exit 1
fi

./build/pgs_bless.exe get --pid "$guard_pid" --token "$token" >"$repo_root/build/smoke_guard_get.txt"
./build/pgs_bless.exe list --json --token "$token" >"$repo_root/build/smoke_list_after_bless.json"

echo "[Smoke] simulating service crash..."
force_stop_process "$service_pid"

service_down=0
for _ in $(seq 1 20); do
  if process_exists "$service_pid"; then
    sleep 0.2
    continue
  fi
  if ./build/pgs_bless.exe ping --token "$token" >/dev/null 2>&1; then
    sleep 0.2
    continue
  fi
  service_down=1
  break
done

if [[ "$service_down" -ne 1 ]]; then
  echo "[Smoke] service did not go down as expected"
  exit 1
fi

echo "[Smoke] removing guarded worker while service is down..."
force_stop_process "$guard_pid"

dead=0
for _ in $(seq 1 20); do
  if process_exists "$guard_pid"; then
    sleep 0.2
    continue
  fi
  dead=1
  break
done

if [[ "$dead" -ne 1 ]]; then
  echo "[Smoke] worker process still alive after forced stop"
  exit 1
fi

echo "[Smoke] restarting service without explicit token to verify persisted restore..."
service_pid="$(start_service_process "" | tr -d '\r\n')"
if [[ ! "$service_pid" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to restart service host process"
  exit 1
fi

ready=0
for _ in $(seq 1 40); do
  if ./build/pgs_bless.exe ping --token "$token" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done

if [[ "$ready" -ne 1 ]]; then
  echo "[Smoke] restored service did not become ready with persisted token"
  exit 1
fi

echo "[Smoke] verifying persisted guard restore..."
restored_list_path="$repo_root/build/smoke_list_restored.json"
restored_list_path_win="$(cygpath -w "$restored_list_path")"
restored_pid=""
for _ in $(seq 1 40); do
  ./build/pgs_bless.exe list --json --token "$token" >"$restored_list_path"
  restored_pid="$(
    "$ps_exe" -NoProfile -Command "\$items = Get-Content -Raw '$restored_list_path_win' | ConvertFrom-Json; \$item = \$items | Where-Object { \$_.path -like '*smoke_worker.exe' } | Select-Object -First 1; if (\$item) { Write-Output \$item.pid }"
  )"
  if [[ -n "$restored_pid" ]]; then
    break
  fi
  sleep 0.25
done

if [[ -z "$restored_pid" ]]; then
  echo "[Smoke] persisted guard was not restored after service restart"
  exit 1
fi

guard_pid="$restored_pid"
./build/pgs_bless.exe get --pid "$guard_pid" --token "$token" >"$repo_root/build/smoke_guard_restored_get.txt"

echo "[Smoke] cleaning restored guard..."
./build/pgs_bless.exe intentional --pid "$guard_pid" --token "$token" >/dev/null
force_stop_process "$guard_pid"

echo "[Smoke] smoke test completed"
