#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="${MINGW_ROOT}/bin:/usr/bin:${PATH:-}"

# Lightweight runtime validation for the most failure-prone paths:
# - console run mode startup
# - token auth + token rotation persistence
# - protocol ping/list/get
# - atomic bless-start flow
# - persisted guard recovery after service restart

token="smoke-token"
rotated_token="smoke-token-rotated"
pgs_port="${PGS_SMOKE_PORT:-12345}"
service_pid=""
service_job_pid=""
guard_pid=""
worker_path_win="$(cygpath -w "$repo_root/build/smoke_worker.exe")"
service_log="$repo_root/build/smoke_service.log"
service_err_log="$repo_root/build/smoke_service.err.log"
smoke_program_data="${PGS_SMOKE_PROGRAMDATA:-$repo_root/build/local_pd_smoke}"
ps_exe="/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

process_exists() {
  local pid="$1"
  "$ps_exe" -NoProfile -Command "if (Get-Process -Id $pid -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >/dev/null 2>&1
}

bless() {
  ./build/pgs_bless.exe --port "$pgs_port" "$@"
}

force_stop_process() {
  local pid="$1"
  "$ps_exe" -NoProfile -Command "Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue" >/dev/null 2>&1 || true
}

start_service_process() {
  local token_value="${1:-}"
  mkdir -p "$smoke_program_data"
  if [[ -n "$token_value" ]]; then
    ProgramData="$(cygpath -w "$smoke_program_data")" ./build/pgs_service.exe run --token "$token_value" --port "$pgs_port" >"$service_log" 2>"$service_err_log" &
  else
    ProgramData="$(cygpath -w "$smoke_program_data")" ./build/pgs_service.exe run --port "$pgs_port" >"$service_log" 2>"$service_err_log" &
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
    bless intentional --pid "$guard_pid" --token "$token" >/dev/null 2>&1 || true
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
  if bless ping --token "$token" >/dev/null 2>&1; then
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
bless list --json --token "$token" >"$repo_root/build/smoke_list_initial.json"

echo "[Smoke] rotating token..."
bless token-set --old-token "$token" --new-token "$rotated_token" --token "$token" >/dev/null
token="$rotated_token"
bless ping --token "$token" >/dev/null

echo "[Smoke] bless-start smoke_worker..."
bless_output="$(
  bless bless-start \
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

bless get --pid "$guard_pid" --token "$token" >"$repo_root/build/smoke_guard_get.txt"
bless list --json --token "$token" >"$repo_root/build/smoke_list_after_bless.json"

echo "[Smoke] simulating service crash..."
force_stop_process "$service_pid"

service_down=0
for _ in $(seq 1 20); do
  if process_exists "$service_pid"; then
    sleep 0.2
    continue
  fi
  if bless ping --token "$token" >/dev/null 2>&1; then
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
  if bless ping --token "$token" >/dev/null 2>&1; then
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
  bless list --json --token "$token" >"$restored_list_path"
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
bless get --pid "$guard_pid" --token "$token" >"$repo_root/build/smoke_guard_restored_get.txt"

echo "[Smoke] cleaning restored guard..."
bless intentional --pid "$guard_pid" --token "$token" >/dev/null
force_stop_process "$guard_pid"


echo "[Smoke] v3: IOCP immediate restart + window-exhaust stop..."

window_list_path="$repo_root/build/smoke_window_list.json"
window_list_win="$(cygpath -w "$window_list_path")"

# echo the pid of any currently-guarded smoke_worker (empty if none)
find_worker_pid() {
  bless list --json --token "$token" >"$window_list_path" 2>/dev/null || true
  "$ps_exe" -NoProfile -Command "\$items = Get-Content -Raw '$window_list_win' | ConvertFrom-Json; \$item = \$items | Where-Object { \$_.path -like '*smoke_worker.exe' } | Select-Object -First 1; if (\$item) { Write-Output \$item.pid }" 2>/dev/null | tr -d '\r\n'
  return 0
}

# register a fresh worker: max-restarts 1 => one restart allowed, second kill stops
window_bless_output="$(
  bless bless-start \
    --path "$worker_path_win" \
    --start-args "--sleep-ms 30000" \
    --max-restarts 1 \
    --restart-window 30 \
    --restart-delay 0 \
    --hash auto \
    --token "$token"
)"
w_guard_pid="$(printf '%s\n' "$window_bless_output" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "$w_guard_pid" ]]; then
  echo "[Smoke] v3: failed to parse worker guard pid"
  exit 1
fi

echo "[Smoke] v3: kill #1 -> expect IOCP-triggered immediate restart..."
force_stop_process "$w_guard_pid"
first_restarted=""
for _ in $(seq 1 20); do
  first_restarted="$(find_worker_pid)"
  if [[ -n "$first_restarted" && "$first_restarted" != "$w_guard_pid" ]]; then
    break
  fi
  sleep 0.2
done
if [[ -z "$first_restarted" || "$first_restarted" == "$w_guard_pid" ]]; then
  echo "[Smoke] v3: worker was NOT restarted after kill #1 (IOCP fast-path)"
  exit 1
fi
echo "[Smoke] v3: kill #1 restarted as pid=$first_restarted"

echo "[Smoke] v3: kill #2 -> expect window-exhaust, NO further restart..."
force_stop_process "$first_restarted"
# give the monitor a moment to (not) restart, then confirm it stays dead
sleep 1
still_dead=1
for _ in $(seq 1 15); do
  cur_pid="$(find_worker_pid)"
  if [[ -n "$cur_pid" && "$cur_pid" != "$w_guard_pid" && "$cur_pid" != "$first_restarted" ]]; then
    still_dead=0
    break
  fi
  sleep 0.3
done
if [[ "$still_dead" -ne 1 ]]; then
  echo "[Smoke] v3: worker was restarted after kill #2 despite max-restarts=1 (window policy not honored)"
  exit 1
fi
echo "[Smoke] v3: window-exhaust stop confirmed (no restart after kill #2)"

# tidy: unregister the exhausted guard if its entry lingers
bless unregister --pid "$first_restarted" --token "$token" >/dev/null 2>&1 || true
echo "[Smoke] smoke test completed"
