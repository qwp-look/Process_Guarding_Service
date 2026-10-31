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
pgs_port="${PGS_SMOKE_PORT:-}"
build_dir="${PGS_BUILD_DIR:-build}"
service_pid=""
service_job_pid=""
bootstrap_service_pid=""
bootstrap_service_job_pid=""
guard_pid=""
http_server_job_pid=""
http_server_win_pid=""
worker_path_win="$(cygpath -w "$repo_root/$build_dir/smoke_worker.exe")"
service_log="$repo_root/$build_dir/smoke_service.log"
service_err_log="$repo_root/$build_dir/smoke_service.err.log"
service_exe_win="$(cygpath -w "$repo_root/$build_dir/pgs_service.exe")"
smoke_program_data="${PGS_SMOKE_PROGRAMDATA:-$repo_root/$build_dir/local_pd_smoke}"
ps_exe="/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
taskkill_exe="/c/Windows/System32/taskkill.exe"

process_exists() {
  local pid="$1"
  "$ps_exe" -NoProfile -Command "if (Get-Process -Id $pid -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >/dev/null 2>&1
}

bless() {
  PGS_AUTH_TOKEN="$token" "$build_dir/pgs_bless.exe" --port "$pgs_port" "$@"
}

expect_bless_failure_contains() {
  local expected="$1"
  shift
  local output=""
  local rc=0
  set +e
  output="$(bless "$@" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 || "$output" != *"$expected"* ]]; then
    echo "[Smoke] expected failure containing '$expected' for: bless $*"
    echo "[Smoke] rc=$rc output=$output"
    exit 1
  fi
}

force_stop_process() {
  local pid="$1"
  for _ in $(seq 1 5); do
    "$taskkill_exe" /PID "$pid" /F /T >/dev/null 2>&1 || true
    "$ps_exe" -NoProfile -Command "\$pidValue = $pid; \$p = Get-Process -Id \$pidValue -ErrorAction SilentlyContinue; if (\$p) { Stop-Process -Id \$pidValue -Force -ErrorAction SilentlyContinue; Wait-Process -Id \$pidValue -Timeout 2 -ErrorAction SilentlyContinue }" >/dev/null 2>&1 || true
    if ! process_exists "$pid"; then
      return 0
    fi
    sleep 0.2
  done
}

json_guard_field() {
  local json_path="$1"
  local field_name="$2"
  local json_path_win
  json_path_win="$(cygpath -w "$json_path")"
  "$ps_exe" -NoProfile -Command "\$item = Get-Content -Raw '$json_path_win' | ConvertFrom-Json | Select-Object -First 1; if (\$item) { Write-Output \$item.$field_name }" 2>/dev/null | tr -d '\r\n'
}

json_guard_field_by_pid() {
  local json_path="$1"
  local pid="$2"
  local field_name="$3"
  local json_path_win
  json_path_win="$(cygpath -w "$json_path")"
  "$ps_exe" -NoProfile -Command "\$items = Get-Content -Raw '$json_path_win' | ConvertFrom-Json; \$item = \$items | Where-Object { [string]\$_.pid -eq '$pid' } | Select-Object -First 1; if (\$item) { Write-Output \$item.$field_name }" 2>/dev/null | tr -d '\r\n'
}

json_guard_field_by_id() {
  local json_path="$1"
  local guard_id="$2"
  local field_name="$3"
  local json_path_win
  json_path_win="$(cygpath -w "$json_path")"
  "$ps_exe" -NoProfile -Command "\$items = Get-Content -Raw '$json_path_win' | ConvertFrom-Json; \$item = \$items | Where-Object { [string]\$_.guard_id -eq '$guard_id' } | Select-Object -First 1; if (\$item) { Write-Output \$item.$field_name }" 2>/dev/null | tr -d '\r\n'
}

find_available_port() {
  local port=""
  port="$("$ps_exe" -NoProfile -Command "\$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 0); \$listener.Start(); \$port = \$listener.LocalEndpoint.Port; \$listener.Stop(); Write-Output \$port" 2>/dev/null | tr -d '\r\n[:space:]')" || true
  if [[ "$port" =~ ^[0-9]+$ && "$port" != "${pgs_port:-}" ]]; then
    printf '%s\n' "$port"
    return 0
  fi
  local base="${PGS_SMOKE_FALLBACK_PORT_BASE:-24000}"
  local candidate=""
  for offset in $(seq 0 200); do
    candidate=$((base + (RANDOM % 20000) + offset))
    if [[ "$candidate" == "${pgs_port:-}" ]]; then
      continue
    fi
    if "$ps_exe" -NoProfile -Command "\$listener = \$null; try { \$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), $candidate); \$listener.Start(); exit 0 } catch { exit 1 } finally { if (\$listener) { \$listener.Stop() } }" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

wait_health_status() {
  local pid="$1"
  local expected="$2"
  local out_path="$3"
  local status=""
  for _ in $(seq 1 30); do
    bless get --pid "$pid" --json >"$out_path"
    status="$(json_guard_field "$out_path" health_status)"
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_port_open() {
  local port="$1"
  "$ps_exe" -NoProfile -Command "\$port = $port; for (\$i = 0; \$i -lt 40; \$i++) { \$client = New-Object System.Net.Sockets.TcpClient; try { \$iar = \$client.BeginConnect('127.0.0.1', \$port, \$null, \$null); if (\$iar.AsyncWaitHandle.WaitOne(250)) { \$client.EndConnect(\$iar); \$stream = \$client.GetStream(); \$nl = [string][char]13 + [string][char]10; \$request = 'GET /ready HTTP/1.1' + \$nl + 'Host: 127.0.0.1' + \$nl + 'Connection: close' + \$nl + \$nl; \$bytes = [System.Text.Encoding]::ASCII.GetBytes(\$request); \$stream.Write(\$bytes, 0, \$bytes.Length); \$stream.Flush(); \$client.Close(); exit 0 } } catch { } finally { \$client.Close() }; Start-Sleep -Milliseconds 100 }; exit 1" >/dev/null 2>&1
}

start_http_status_server() {
  local port="$1"
  "$ps_exe" -NoProfile -Command "\$port = $port; \$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), \$port); \$listener.Start(); try { while (\$true) { \$client = \$listener.AcceptTcpClient(); try { \$stream = \$client.GetStream(); \$stream.ReadTimeout = 2000; \$buffer = New-Object byte[] 1024; try { [void]\$stream.Read(\$buffer, 0, \$buffer.Length) } catch { }; \$nl = [string][char]13 + [string][char]10; \$response = 'HTTP/1.1 500 Internal Server Error' + \$nl + 'Content-Length: 0' + \$nl + 'Connection: close' + \$nl + \$nl; \$bytes = [System.Text.Encoding]::ASCII.GetBytes(\$response); \$stream.Write(\$bytes, 0, \$bytes.Length); \$stream.Flush() } catch { } finally { \$client.Close() } } } finally { \$listener.Stop() }" >/dev/null 2>&1 &
  local job_pid=$!
  local win_pid=""
  for _ in $(seq 1 20); do
    if [[ -r "/proc/$job_pid/winpid" ]]; then
      win_pid="$(tr -d '\r\n' <"/proc/$job_pid/winpid")"
      break
    fi
    sleep 0.05
  done
  echo "$job_pid;$win_pid"
}

start_http_timeout_server() {
  local port="$1"
  "$ps_exe" -NoProfile -Command "\$port = $port; \$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), \$port); \$listener.Start(); try { while (\$true) { \$client = \$listener.AcceptTcpClient(); try { \$stream = \$client.GetStream(); \$stream.ReadTimeout = 500; \$buffer = New-Object byte[] 1024; try { [void]\$stream.Read(\$buffer, 0, \$buffer.Length) } catch { }; Start-Sleep -Milliseconds 2500; \$nl = [string][char]13 + [string][char]10; \$response = 'HTTP/1.1 200 OK' + \$nl + 'Content-Length: 0' + \$nl + 'Connection: close' + \$nl + \$nl; \$bytes = [System.Text.Encoding]::ASCII.GetBytes(\$response); try { \$stream.Write(\$bytes, 0, \$bytes.Length); \$stream.Flush() } catch { } } catch { } finally { \$client.Close() } } } finally { \$listener.Stop() }" >/dev/null 2>&1 &
  local job_pid=$!
  local win_pid=""
  for _ in $(seq 1 20); do
    if [[ -r "/proc/$job_pid/winpid" ]]; then
      win_pid="$(tr -d '\r\n' <"/proc/$job_pid/winpid")"
      break
    fi
    sleep 0.05
  done
  echo "$job_pid;$win_pid"
}

force_stop_service_host() {
  if [[ -n "$service_pid" ]]; then
    force_stop_process "$service_pid"
  fi
  if [[ -n "$service_job_pid" ]]; then
    kill "$service_job_pid" >/dev/null 2>&1 || true
  fi
}

start_service_process() {
  local token_value="${1:-}"
  mkdir -p "$smoke_program_data"
  if [[ -n "$token_value" ]]; then
    PGS_SERVICE_TOKEN="$token_value" ProgramData="$(cygpath -w "$smoke_program_data")" "$build_dir/pgs_service.exe" run --port "$pgs_port" --enable-modules >"$service_log" 2>"$service_err_log" &
  else
    env -u PGS_SERVICE_TOKEN ProgramData="$(cygpath -w "$smoke_program_data")" "$build_dir/pgs_service.exe" run --port "$pgs_port" --enable-modules >"$service_log" 2>"$service_err_log" &
  fi

  service_job_pid=$!
  local actual_pid=""
  for _ in $(seq 1 40); do
    actual_pid="$(
      "$ps_exe" -NoProfile -Command "\$path = '$service_exe_win'; \$p = Get-Process pgs_service -ErrorAction SilentlyContinue | Where-Object { \$_.Path -eq \$path } | Sort-Object StartTime -Descending | Select-Object -First 1; if (\$p) { Write-Output \$p.Id }" 2>/dev/null | tr -d '\r\n'
    )"
    if [[ "$actual_pid" =~ ^[0-9]+$ ]]; then
      echo "$actual_pid"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

run_bootstrap_token_smoke() {
  local bootstrap_port=""
  local bootstrap_program_data=""
  local bootstrap_log=""
  local bootstrap_err_log=""
  local bootstrap_token_file=""
  local bootstrap_token=""
  local actual_pid=""
  local ready=0

  bootstrap_port="$(find_available_port)"
  if [[ ! "$bootstrap_port" =~ ^[0-9]+$ ]]; then
    echo "[Smoke] bootstrap token smoke could not allocate port"
    exit 1
  fi
  bootstrap_program_data="$repo_root/$build_dir/local_pd_smoke_bootstrap_$$"
  bootstrap_log="$repo_root/$build_dir/smoke_bootstrap_service.log"
  bootstrap_err_log="$repo_root/$build_dir/smoke_bootstrap_service.err.log"
  bootstrap_token_file="$bootstrap_program_data/ProcessGuard/state/pgs_initial_token.txt"

  mkdir -p "$bootstrap_program_data"
  env -u PGS_SERVICE_TOKEN ProgramData="$(cygpath -w "$bootstrap_program_data")" "$build_dir/pgs_service.exe" run --port "$bootstrap_port" --enable-modules >"$bootstrap_log" 2>"$bootstrap_err_log" &
  bootstrap_service_job_pid=$!

  for _ in $(seq 1 40); do
    actual_pid="$(
      "$ps_exe" -NoProfile -Command "\$path = '$service_exe_win'; \$p = Get-Process pgs_service -ErrorAction SilentlyContinue | Where-Object { \$_.Path -eq \$path } | Sort-Object StartTime -Descending | Select-Object -First 1; if (\$p) { Write-Output \$p.Id }" 2>/dev/null | tr -d '\r\n'
    )"
    if [[ "$actual_pid" =~ ^[0-9]+$ ]]; then
      bootstrap_service_pid="$actual_pid"
      break
    fi
    sleep 0.1
  done
  if [[ ! "$bootstrap_service_pid" =~ ^[0-9]+$ ]]; then
    echo "[Smoke] bootstrap token smoke failed to start service host"
    exit 1
  fi

  for _ in $(seq 1 40); do
    if [[ -s "$bootstrap_token_file" ]]; then
      bootstrap_token="$(tr -d '\r\n' <"$bootstrap_token_file" 2>/dev/null || true)"
      break
    fi
    sleep 0.25
  done
  if [[ ! "$bootstrap_token" =~ ^[0-9a-fA-F]{64}$ ]]; then
    if [[ -f "$bootstrap_token_file" ]] && ! cat "$bootstrap_token_file" >/dev/null 2>&1; then
      # P0-04 hardening: the bootstrap token file DACL is SYSTEM+Administrators
      # only. A non-elevated smoke shell cannot read it back, so skip this
      # section gracefully instead of failing; CI runs elevated and covers it.
      echo "[Smoke] SKIP bootstrap token read check (token file ACL is SYSTEM+Administrators only;"
      echo "[Smoke]       rerun from an elevated shell to exercise this section)"
      force_stop_process "$bootstrap_service_pid"
      kill "$bootstrap_service_job_pid" >/dev/null 2>&1 || true
      bootstrap_service_pid=""
      bootstrap_service_job_pid=""
      return 0
    fi
    echo "[Smoke] bootstrap token file was not written with a 64-hex token"
    echo "[Smoke] token path: $bootstrap_token_file"
    exit 1
  fi

  for _ in $(seq 1 40); do
    if PGS_AUTH_TOKEN="$bootstrap_token" "$build_dir/pgs_bless.exe" --port "$bootstrap_port" ping >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.25
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "[Smoke] bootstrap token from file did not authenticate"
    exit 1
  fi

  force_stop_process "$bootstrap_service_pid"
  kill "$bootstrap_service_job_pid" >/dev/null 2>&1 || true
  bootstrap_service_pid=""
  bootstrap_service_job_pid=""
}

cleanup() {
  set +e

  if [[ -n "$bootstrap_service_pid" ]]; then
    force_stop_process "$bootstrap_service_pid"
  fi
  if [[ -n "$bootstrap_service_job_pid" ]]; then
    kill "$bootstrap_service_job_pid" >/dev/null 2>&1 || true
  fi

  if [[ -n "$guard_pid" ]]; then
    bless intentional --pid "$guard_pid" >/dev/null 2>&1 || true
    force_stop_process "$guard_pid"
  fi

  if [[ -n "$http_server_job_pid" ]]; then
    if [[ -n "$http_server_win_pid" ]]; then
      force_stop_process "$http_server_win_pid"
    fi
    kill "$http_server_job_pid" >/dev/null 2>&1 || true
  fi

  if [[ -n "$service_pid" || -n "$service_job_pid" ]]; then
    force_stop_service_host
  fi
}

trap cleanup EXIT

if [[ -z "$pgs_port" ]]; then
  pgs_port="$(find_available_port)"
fi
if [[ ! "$pgs_port" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] invalid PGS smoke port: $pgs_port"
  exit 1
fi
echo "[Smoke] using port $pgs_port"

# P0-03: startup is audit-only (no auto-repair). Dev/build trees usually inherit
# broad ACLs, so explicitly repair the modules trust boundary before any
# --enable-modules service start. Production installs should ship repaired ACLs
# or run `doctor repair-modules-acl` once as admin.
echo "[Smoke] repairing modules ACL (explicit doctor repair, not startup auto-fix)..."
if ! "$build_dir/pgs_bless.exe" doctor repair-modules-acl --json >/dev/null; then
  echo "[Smoke] doctor repair-modules-acl failed"
  exit 1
fi
doctor_acl_pre="$("$build_dir/pgs_bless.exe" doctor --json 2>/dev/null || true)"
if [[ "$doctor_acl_pre" != *'"id":"modules_acl_recursive","status":"ok"'* ]]; then
  echo "[Smoke] modules_acl_recursive not ok after explicit repair: $doctor_acl_pre"
  exit 1
fi
echo "[Smoke] modules ACL repair ok"

echo "[Smoke] bootstrap token first-start path..."
run_bootstrap_token_smoke
echo "[Smoke] bootstrap token first-start path ok"

echo "[Smoke] Starting console PGS..."
service_pid="$(start_service_process "$token" | tr -d '\r\n')"
if [[ ! "$service_pid" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to start service host process"
  exit 1
fi

ready=0
for _ in $(seq 1 40); do
  if bless ping >/dev/null 2>&1; then
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
version_text="$(bless version)"
if [[ ! "$version_text" =~ ^OK[[:space:]]protocol=3 ]]; then
  echo "[Smoke] unexpected version response: $version_text"
  exit 1
fi
stats_text="$(bless stats)"
if [[ ! "$stats_text" =~ ^OK[[:space:]]guards= ]]; then
  echo "[Smoke] unexpected stats response: $stats_text"
  exit 1
fi
echo "[Smoke] protocol contract ok"
bless service-guard policy-clear --confirm >/dev/null
doctor_json="$(bless doctor --json)"
if [[ "$doctor_json" != *'"id":"modules_acl_recursive","status":"ok"'* ]]; then
  echo "[Smoke] modules_acl_recursive missing or not ok: $doctor_json"
  exit 1
fi
if [[ "$doctor_json" != *'bad_count='* || "$doctor_json" != *'first_bad_path_b64='* || "$doctor_json" != *'reason='* ]]; then
  echo "[Smoke] doctor JSON missing modules_acl_recursive fields: $doctor_json"
  exit 1
fi
# P0-04: bootstrap token ACL check is always present (ok|error|info).
if [[ "$doctor_json" != *'"id":"bootstrap_token_acl"'* ]]; then
  echo "[Smoke] doctor JSON missing bootstrap_token_acl check: $doctor_json"
  exit 1
fi
if [[ "$doctor_json" != *'present='* || "$doctor_json" != *'reason='* ]]; then
  echo "[Smoke] doctor JSON missing bootstrap_token_acl fields: $doctor_json"
  exit 1
fi
if [[ "$doctor_json" != *'"id":"artifact_store"'* ]]; then
  echo "[Smoke] doctor JSON missing artifact_store check: $doctor_json"
  exit 1
fi
if [[ "$doctor_json" != *'max_artifact_bytes='* || "$doctor_json" != *'max_total_bytes='* ]]; then
  echo "[Smoke] doctor JSON missing artifact quota fields: $doctor_json"
  exit 1
fi
if [[ "$doctor_json" != *'"id":"file_watch"'* || "$doctor_json" != *'max_rules=64'* || "$doctor_json" != *'path_policy=local_absolute'* ]]; then
  echo "[Smoke] doctor JSON missing file_watch policy fields: $doctor_json"
  exit 1
fi
if [[ "$doctor_json" != *'"id":"service_guard"'* || "$doctor_json" != *'mutation_policy=confirm_plus_allowlist_plus_protected_deny'* || "$doctor_json" != *'protected_services='* ]]; then
  echo "[Smoke] doctor JSON missing service_guard policy fields: $doctor_json"
  exit 1
fi
bless notify status >/dev/null
echo "[Smoke] notify module ok"
metrics_summary="$(bless metrics summary)"
if [[ ! "$metrics_summary" =~ ^OK[[:space:]]guards= ]]; then
  echo "[Smoke] metrics summary failed: $metrics_summary"
  exit 1
fi
backup_status="$(bless backup status)"
if [[ ! "$backup_status" =~ ^OK[[:space:]]data_dir_b64= ]]; then
  echo "[Smoke] backup status failed: $backup_status"
  exit 1
fi
eventlog_status="$(bless eventlog status)"
if [[ ! "$eventlog_status" =~ ^OK[[:space:]]source=Application ]]; then
  echo "[Smoke] eventlog status failed: $eventlog_status"
  exit 1
fi
dump_status="$(bless dump status)"
if [[ ! "$dump_status" =~ ^OK[[:space:]]enabled=1 ]]; then
  echo "[Smoke] dump status failed: $dump_status"
  exit 1
fi
service_guard_status="$(bless service-guard status)"
if [[ ! "$service_guard_status" =~ ^OK[[:space:]]scm=local || "$service_guard_status" != *"mutation_policy=confirm_plus_allowlist_plus_protected_deny"* || "$service_guard_status" != *"allowlist_mode=disabled"* || "$service_guard_status" != *"protected_services="* ]]; then
  echo "[Smoke] service-guard status failed: $service_guard_status"
  exit 1
fi
service_guard_query="$(bless service-guard query --name EventLog)"
if [[ ! "$service_guard_query" =~ ^OK[[:space:]]name=EventLog ]]; then
  echo "[Smoke] service-guard query failed: $service_guard_query"
  exit 1
fi
expect_bless_failure_contains "policy update requires confirm=1" service-guard policy --allow PGS_Smoke_Synthetic_Service
service_guard_policy_set="$(bless service-guard policy --allow PGS_Smoke_Synthetic_Service --confirm)"
if [[ "$service_guard_policy_set" != OK\ mutation_policy=* || "$service_guard_policy_set" != *"allowlist_mode=enabled"* || "$service_guard_policy_set" != *"allow_count=1"* ]]; then
  echo "[Smoke] service-guard policy set failed: $service_guard_policy_set"
  exit 1
fi
service_guard_policy_clear="$(bless service-guard policy-clear --confirm)"
if [[ "$service_guard_policy_clear" != OK\ mutation_policy=* || "$service_guard_policy_clear" != *"allowlist_mode=disabled"* ]]; then
  echo "[Smoke] service-guard policy clear failed: $service_guard_policy_clear"
  exit 1
fi
file_watch_status="$(bless file-watch status)"
if [[ ! "$file_watch_status" =~ ^OK[[:space:]]rules= || "$file_watch_status" != *"max_rules=64"* || "$file_watch_status" != *"path_policy=local_absolute"* ]]; then
  echo "[Smoke] file-watch status failed: $file_watch_status"
  exit 1
fi
file_watch_target="$repo_root/$build_dir/smoke_file_watch_target.txt"
printf 'one\n' >"$file_watch_target"
file_watch_add="$(bless file-watch add --path "$(cygpath -w "$file_watch_target")" --id smoke_fw --action none)"
if [[ ! "$file_watch_add" =~ ^OK[[:space:]]id=smoke_fw ]]; then
  echo "[Smoke] file-watch add failed: $file_watch_add"
  exit 1
fi
printf 'two\n' >>"$file_watch_target"
file_watch_check="$(bless file-watch check)"
if [[ ! "$file_watch_check" =~ changed=1 ]]; then
  echo "[Smoke] file-watch check failed: $file_watch_check"
  exit 1
fi
bless file-watch remove --id smoke_fw >/dev/null
policy_status="$(bless policy-template status)"
if [[ ! "$policy_status" =~ ^OK[[:space:]]templates= ]]; then
  echo "[Smoke] policy-template status failed: $policy_status"
  exit 1
fi
policy_set="$(bless policy-template set --name smoke_policy --max-restarts 2 --restart-window 30 --restart-delay 0)"
if [[ ! "$policy_set" =~ ^OK[[:space:]]name=smoke_policy ]]; then
  echo "[Smoke] policy-template set failed: $policy_set"
  exit 1
fi
policy_list="$(bless policy-template list)"
if [[ ! "$policy_list" =~ TEMPLATE[[:space:]]name=smoke_policy ]]; then
  echo "[Smoke] policy-template list failed: $policy_list"
  exit 1
fi
bless policy-template remove --name smoke_policy >/dev/null
echo "[Smoke] high-risk module negative checks..."
expect_bless_failure_contains "dump collect requires confirm=1" dump collect --pid "$service_pid"
expect_bless_failure_contains "service mutation requires confirm=1" service-guard start --name EventLog
expect_bless_failure_contains "service mutation denied by policy: protected-service" service-guard stop --name EventLog --confirm
service_guard_events="$(bless events list --limit 256)"
if [[ "$service_guard_events" != *"TYPE=service_guard.mutation-denied"* ]]; then
  echo "[Smoke] service_guard mutation denial audit event missing"
  echo "$service_guard_events"
  exit 1
fi
missing_watch_target="$repo_root/$build_dir/smoke_file_watch_missing.txt"
rm -f "$missing_watch_target"
expect_bless_failure_contains "watched file is not readable" file-watch add --path "$(cygpath -w "$missing_watch_target")" --id smoke_missing --action none
if [[ -f /c/Windows/win.ini ]]; then
  expect_bless_failure_contains "path is denied by policy" file-watch add --path "$(cygpath -w /c/Windows/win.ini)" --id smoke_windows --action none
fi
permissive_status="$(bless module permissive status)"
if [[ "$permissive_status" != OK\ permissive=* ]]; then
  echo "[Smoke] module permissive status failed: $permissive_status"
  exit 1
fi
expect_bless_failure_contains "module permissive on requires confirm=1" module permissive on
permissive_on="$(bless module permissive on --confirm)"
if [[ "$permissive_on" != OK\ permissive=1* ]]; then
  echo "[Smoke] module permissive on failed: $permissive_on"
  exit 1
fi
permissive_off="$(bless module permissive off)"
if [[ "$permissive_off" != OK\ permissive=0* ]]; then
  echo "[Smoke] module permissive off failed: $permissive_off"
  exit 1
fi
echo "[Smoke] high-risk module negative checks ok"
echo "[Smoke] metrics/backup/eventlog/new modules ok"
echo "[Smoke] report artifact and operation store..."
bless module artifact cleanup --all --verify >/dev/null || true
report_artifact_output="$(bless report backup --artifact --limit 5)"
operation_id="$(printf '%s\n' "$report_artifact_output" | sed -n 's/.*operation_id=\([^; ]*\).*/\1/p' | head -n 1)"
artifact_id="$(printf '%s\n' "$report_artifact_output" | sed -n 's/.*artifact_id=\([^; ]*\).*/\1/p' | head -n 1)"
if [[ -z "$operation_id" || -z "$artifact_id" ]]; then
  echo "[Smoke] failed to parse operation/artifact ids: $report_artifact_output"
  exit 1
fi
bless module op-status "$operation_id" --json >"$repo_root/$build_dir/smoke_operation_status.json"
if ! grep -q '"status":"succeeded"' "$repo_root/$build_dir/smoke_operation_status.json"; then
  echo "[Smoke] operation status did not reach succeeded"
  exit 1
fi
bless module artifact get "$artifact_id" --json >"$repo_root/$build_dir/smoke_artifact_meta.json"
if ! grep -q '"filename":"pgs-backup.txt"' "$repo_root/$build_dir/smoke_artifact_meta.json"; then
  echo "[Smoke] artifact metadata missing expected filename"
  exit 1
fi
if ! grep -q '"sensitive":true' "$repo_root/$build_dir/smoke_artifact_meta.json" || ! grep -q '"sensitivity":"medium"' "$repo_root/$build_dir/smoke_artifact_meta.json"; then
  echo "[Smoke] artifact metadata missing expected sensitivity fields"
  cat "$repo_root/$build_dir/smoke_artifact_meta.json"
  exit 1
fi
bless module artifact policy --ttl-ms 60000 --max-artifact-bytes 1048576 --max-total-bytes 2097152 --auto-cleanup --verify-on-status --json >"$repo_root/$build_dir/smoke_artifact_policy.json"
if ! grep -q '"ttl_ms":60000' "$repo_root/$build_dir/smoke_artifact_policy.json" || ! grep -q '"verify_on_status":true' "$repo_root/$build_dir/smoke_artifact_policy.json" || ! grep -q '"max_artifact_bytes":1048576' "$repo_root/$build_dir/smoke_artifact_policy.json" || ! grep -q '"max_total_bytes":2097152' "$repo_root/$build_dir/smoke_artifact_policy.json"; then
  echo "[Smoke] artifact policy JSON did not reflect requested settings"
  cat "$repo_root/$build_dir/smoke_artifact_policy.json"
  exit 1
fi
bless module artifact status --json >"$repo_root/$build_dir/smoke_artifact_status.json"
if ! grep -q '"count":1' "$repo_root/$build_dir/smoke_artifact_status.json" || ! grep -q '"ttl_ms":60000' "$repo_root/$build_dir/smoke_artifact_status.json" || ! grep -q '"sensitive":1' "$repo_root/$build_dir/smoke_artifact_status.json" || ! grep -q '"max_artifact_bytes":1048576' "$repo_root/$build_dir/smoke_artifact_status.json" || ! grep -q '"max_total_bytes":2097152' "$repo_root/$build_dir/smoke_artifact_status.json"; then
  echo "[Smoke] artifact status JSON missing expected count/policy"
  cat "$repo_root/$build_dir/smoke_artifact_status.json"
  exit 1
fi
artifact_out="$repo_root/$build_dir/smoke_report_artifact.txt"
artifact_download_output="$(bless module artifact get "$artifact_id" --out "$(cygpath -w "$artifact_out")")"
if [[ "$artifact_download_output" != *"sha256="* ]]; then
  echo "[Smoke] artifact download did not report sha256 validation: $artifact_download_output"
  exit 1
fi
if ! grep -q 'PGS backup' "$artifact_out"; then
  echo "[Smoke] downloaded artifact does not contain report content"
  exit 1
fi
events_after_artifact="$(bless events list --limit 512)"
if [[ "$events_after_artifact" != *"TYPE=artifact.download-complete"* ]]; then
  echo "[Smoke] artifact download audit event missing"
  echo "$events_after_artifact"
  exit 1
fi
cleanup_output="$(bless module artifact cleanup --all --verify)"
if [[ "$cleanup_output" != OK\ artifact\ cleanup* ]]; then
  echo "[Smoke] artifact cleanup failed: $cleanup_output"
  exit 1
fi
bless module artifact policy --ttl-ms 86400000 --max-artifact-bytes 16777216 --max-total-bytes 268435456 --auto-cleanup --no-verify-on-status --json >/dev/null
echo "[Smoke] operation/artifact store ok"
bless list --json >"$repo_root/$build_dir/smoke_list_initial.json"

echo "[Smoke] rotating token..."
bless token-set --old-token "$token" --new-token "$rotated_token" >/dev/null
token="$rotated_token"
bless ping >/dev/null

echo "[Smoke] bless-start smoke_worker..."
bless_output="$(
  bless bless-start \
    --path "$worker_path_win" \
    --start-args "--sleep-ms 120000" \
    --max-restarts 1 \
    --hash auto
)"
printf '%s\n' "$bless_output" >"$repo_root/$build_dir/smoke_bless_start.log"

guard_pid="$(printf '%s\n' "$bless_output" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "$guard_pid" ]]; then
  echo "[Smoke] failed to parse guard pid from bless-start output"
  exit 1
fi

bless get --pid "$guard_pid" >"$repo_root/$build_dir/smoke_guard_get.txt"
echo "[Smoke] health-check process probe..."
bless health-check set --pid "$guard_pid" --config-json '{"type":"process","interval_ms":1000,"timeout_ms":500,"failures":1,"action":"event"}' >/dev/null
health_path="$repo_root/$build_dir/smoke_guard_health.json"
if ! wait_health_status "$guard_pid" healthy "$health_path"; then
  echo "[Smoke] health-check process probe did not become healthy"
  exit 1
fi
bless health-check clear --pid "$guard_pid" >/dev/null

echo "[Smoke] health-check TCP negative probe..."
tcp_closed_port="$(find_available_port)"
if [[ ! "$tcp_closed_port" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to allocate TCP closed test port"
  exit 1
fi
bless health-check set --pid "$guard_pid" --config-json "{\"type\":\"tcp\",\"host\":\"127.0.0.1\",\"port\":$tcp_closed_port,\"interval_ms\":1000,\"timeout_ms\":300,\"failures\":1,\"action\":\"event\"}" >/dev/null
if ! wait_health_status "$guard_pid" unhealthy "$health_path"; then
  echo "[Smoke] health-check TCP negative probe did not become unhealthy"
  cat "$health_path"
  exit 1
fi
tcp_message="$(json_guard_field "$health_path" health_last_message)"
if [[ "$tcp_message" != tcp\ connect\ failed* ]]; then
  echo "[Smoke] health-check TCP negative message was unexpected: $tcp_message"
  exit 1
fi
bless health-check clear --pid "$guard_pid" >/dev/null

echo "[Smoke] health-check HTTP unexpected-status probe..."
http_status_port="$(find_available_port)"
if [[ ! "$http_status_port" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to allocate HTTP status test port"
  exit 1
fi
http_server_ids="$(start_http_status_server "$http_status_port")"
http_server_job_pid="${http_server_ids%%;*}"
http_server_win_pid="${http_server_ids#*;}"
if [[ ! "$http_server_job_pid" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to start HTTP status test server"
  exit 1
fi
if ! wait_port_open "$http_status_port"; then
  echo "[Smoke] HTTP status test server did not become ready"
  exit 1
fi
bless health-check set --pid "$guard_pid" --config-json "{\"type\":\"http\",\"url\":\"http://127.0.0.1:$http_status_port/health\",\"expected_status\":200,\"interval_ms\":1000,\"timeout_ms\":500,\"failures\":1,\"action\":\"event\"}" >/dev/null
if ! wait_health_status "$guard_pid" unhealthy "$health_path"; then
  echo "[Smoke] health-check HTTP unexpected-status probe did not become unhealthy"
  cat "$health_path"
  exit 1
fi
http_message="$(json_guard_field "$health_path" health_last_message)"
if [[ "$http_message" != http\ unexpected\ status=500* ]]; then
  echo "[Smoke] health-check HTTP negative message was unexpected: $http_message"
  exit 1
fi
bless health-check clear --pid "$guard_pid" >/dev/null
if [[ -n "$http_server_win_pid" ]]; then
  force_stop_process "$http_server_win_pid"
fi
kill "$http_server_job_pid" >/dev/null 2>&1 || true
http_server_job_pid=""
http_server_win_pid=""

echo "[Smoke] health-check TCP DNS failure probe..."
bless health-check set --pid "$guard_pid" --config-json '{"type":"tcp","host":"not a valid host","port":80,"interval_ms":1000,"timeout_ms":300,"failures":1,"action":"event"}' >/dev/null
if ! wait_health_status "$guard_pid" unhealthy "$health_path"; then
  echo "[Smoke] health-check TCP DNS failure probe did not become unhealthy"
  cat "$health_path"
  exit 1
fi
dns_message="$(json_guard_field "$health_path" health_last_message)"
if [[ "$dns_message" != tcp\ resolve\ failed* ]]; then
  echo "[Smoke] health-check DNS failure message was unexpected: $dns_message"
  exit 1
fi
bless health-check clear --pid "$guard_pid" >/dev/null

echo "[Smoke] health-check HTTP timeout probe..."
http_timeout_port="$(find_available_port)"
if [[ ! "$http_timeout_port" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to allocate HTTP timeout test port"
  exit 1
fi
http_server_ids="$(start_http_timeout_server "$http_timeout_port")"
http_server_job_pid="${http_server_ids%%;*}"
http_server_win_pid="${http_server_ids#*;}"
if [[ ! "$http_server_job_pid" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to start HTTP timeout test server"
  exit 1
fi
if ! wait_port_open "$http_timeout_port"; then
  echo "[Smoke] HTTP timeout test server did not become ready"
  exit 1
fi
bless health-check set --pid "$guard_pid" --config-json "{\"type\":\"http\",\"url\":\"http://127.0.0.1:$http_timeout_port/slow\",\"expected_status\":200,\"interval_ms\":1000,\"timeout_ms\":300,\"failures\":1,\"action\":\"event\"}" >/dev/null
if ! wait_health_status "$guard_pid" unhealthy "$health_path"; then
  echo "[Smoke] health-check HTTP timeout probe did not become unhealthy"
  cat "$health_path"
  exit 1
fi
timeout_message="$(json_guard_field "$health_path" health_last_message)"
if [[ "$timeout_message" != http\ request\ failed* ]]; then
  echo "[Smoke] health-check HTTP timeout message was unexpected: $timeout_message"
  exit 1
fi
bless health-check clear --pid "$guard_pid" >/dev/null
if [[ -n "$http_server_win_pid" ]]; then
  force_stop_process "$http_server_win_pid"
fi
kill "$http_server_job_pid" >/dev/null 2>&1 || true
http_server_job_pid=""
http_server_win_pid=""

echo "[Smoke] health-check restart action E2E..."
health_restart_output="$(
  bless bless-start \
    --path "$worker_path_win" \
    --start-args "--sleep-ms 60000" \
    --max-restarts 3 \
    --restart-window 60 \
    --restart-delay 0 \
    --hash auto
)"
health_restart_pid="$(printf '%s\n' "$health_restart_output" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "$health_restart_pid" ]]; then
  echo "[Smoke] failed to parse health restart pid: $health_restart_output"
  exit 1
fi
health_action_path="$repo_root/$build_dir/smoke_health_action_list.json"
health_action_win="$(cygpath -w "$health_action_path")"
bless list --json >"$health_action_path"
health_restart_guard_id="$(json_guard_field_by_pid "$health_action_path" "$health_restart_pid" guard_id)"
if [[ -z "$health_restart_guard_id" ]]; then
  echo "[Smoke] failed to resolve health restart guard id"
  cat "$health_action_path"
  exit 1
fi
health_restart_port="$(find_available_port)"
if [[ ! "$health_restart_port" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to allocate health restart closed port"
  exit 1
fi
bless health-check set --pid "$health_restart_pid" --config-json "{\"type\":\"tcp\",\"host\":\"127.0.0.1\",\"port\":$health_restart_port,\"interval_ms\":1000,\"timeout_ms\":300,\"failures\":2,\"action\":\"restart\"}" >/dev/null
health_restarted_pid=""
for _ in $(seq 1 30); do
  bless list --json >"$health_action_path"
  health_restarted_pid="$(json_guard_field_by_id "$health_action_path" "$health_restart_guard_id" pid)"
  if [[ -n "$health_restarted_pid" && "$health_restarted_pid" != "0" && "$health_restarted_pid" != "$health_restart_pid" ]]; then
    break
  fi
  sleep 0.25
done
if [[ -z "$health_restarted_pid" || "$health_restarted_pid" == "$health_restart_pid" || "$health_restarted_pid" == "0" ]]; then
  echo "[Smoke] health-check restart action did not produce a new pid"
  cat "$health_action_path"
  exit 1
fi
bless health-check clear --pid "$health_restarted_pid" >/dev/null 2>&1 || true
bless intentional --pid "$health_restarted_pid" >/dev/null 2>&1 || true
force_stop_process "$health_restarted_pid"
if process_exists "$health_restart_pid"; then
  force_stop_process "$health_restart_pid"
fi

echo "[Smoke] health-check quarantine action E2E..."
health_quarantine_output="$(
  bless bless-start \
    --path "$worker_path_win" \
    --start-args "--sleep-ms 60000" \
    --max-restarts 3 \
    --restart-window 60 \
    --restart-delay 0 \
    --hash auto
)"
health_quarantine_pid="$(printf '%s\n' "$health_quarantine_output" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "$health_quarantine_pid" ]]; then
  echo "[Smoke] failed to parse health quarantine pid: $health_quarantine_output"
  exit 1
fi
bless list --json >"$health_action_path"
health_quarantine_guard_id="$(json_guard_field_by_pid "$health_action_path" "$health_quarantine_pid" guard_id)"
if [[ -z "$health_quarantine_guard_id" ]]; then
  echo "[Smoke] failed to resolve health quarantine guard id"
  cat "$health_action_path"
  exit 1
fi
health_quarantine_port="$(find_available_port)"
if [[ ! "$health_quarantine_port" =~ ^[0-9]+$ ]]; then
  echo "[Smoke] failed to allocate health quarantine closed port"
  exit 1
fi
bless health-check set --pid "$health_quarantine_pid" --config-json "{\"type\":\"tcp\",\"host\":\"127.0.0.1\",\"port\":$health_quarantine_port,\"interval_ms\":10000,\"timeout_ms\":300,\"failures\":1,\"action\":\"quarantine\"}" >/dev/null
health_quarantine_status=""
health_quarantine_code=""
for _ in $(seq 1 30); do
  bless list --json >"$health_action_path"
  health_quarantine_status="$(json_guard_field_by_id "$health_action_path" "$health_quarantine_guard_id" status)"
  health_quarantine_code="$(json_guard_field_by_id "$health_action_path" "$health_quarantine_guard_id" last_failure_code)"
  if [[ "$health_quarantine_status" == "quarantined" && "$health_quarantine_code" == "health.failed" ]]; then
    break
  fi
  sleep 0.25
done
if [[ "$health_quarantine_status" != "quarantined" || "$health_quarantine_code" != "health.failed" ]]; then
  echo "[Smoke] health-check quarantine action did not quarantine guard"
  cat "$health_action_path"
  exit 1
fi
bless guard clear-quarantine --id "$health_quarantine_guard_id" >/dev/null
if process_exists "$health_quarantine_pid"; then
  force_stop_process "$health_quarantine_pid"
fi

bless list --json >"$repo_root/$build_dir/smoke_list_after_bless.json"
if ! grep -q '"app_kind"' "$repo_root/$build_dir/smoke_list_after_bless.json" ||
   ! grep -q '"restart_window"' "$repo_root/$build_dir/smoke_list_after_bless.json"; then
  echo "[Smoke] list --json is missing v3 guard-policy fields"
  exit 1
fi

echo "[Smoke] simulating service crash..."
force_stop_service_host

service_down=0
for _ in $(seq 1 20); do
  if process_exists "$service_pid"; then
    sleep 0.2
    continue
  fi
  if bless ping >/dev/null 2>&1; then
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
  if bless ping >/dev/null 2>&1; then
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
restored_list_path="$repo_root/$build_dir/smoke_list_restored.json"
restored_list_path_win="$(cygpath -w "$restored_list_path")"
restored_pid=""
for _ in $(seq 1 40); do
  bless list --json >"$restored_list_path"
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
bless get --pid "$guard_pid" >"$repo_root/$build_dir/smoke_guard_restored_get.txt"

echo "[Smoke] cleaning restored guard..."
bless intentional --pid "$guard_pid" >/dev/null
force_stop_process "$guard_pid"


echo "[Smoke] v3: IOCP immediate restart + window-exhaust stop..."

window_list_path="$repo_root/$build_dir/smoke_window_list.json"
window_list_win="$(cygpath -w "$window_list_path")"

# echo the pid of any currently-guarded smoke_worker (empty if none)
find_worker_pid() {
  bless list --json >"$window_list_path" 2>/dev/null || true
  "$ps_exe" -NoProfile -Command "\$items = Get-Content -Raw '$window_list_win' | ConvertFrom-Json; \$item = \$items | Where-Object { \$_.path -like '*smoke_worker.exe' -and \$_.pid -ne '0' -and \$_.status -ne 'quarantined' } | Select-Object -First 1; if (\$item) { Write-Output \$item.pid }" 2>/dev/null | tr -d '\r\n'
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
    --hash auto
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
echo "[Smoke] v3: window-exhaust quarantine confirmed (no restart after kill #2)"

quarantine_id="$(
  "$ps_exe" -NoProfile -Command "\$items = Get-Content -Raw '$window_list_win' | ConvertFrom-Json; \$item = \$items | Where-Object { \$_.path -like '*smoke_worker.exe' -and \$_.status -eq 'quarantined' -and \$_.quarantined -eq '1' } | Select-Object -First 1; if (\$item) { Write-Output \$item.guard_id }" 2>/dev/null | tr -d '\r\n'
)"
if [[ -z "$quarantine_id" ]]; then
  echo "[Smoke] v3: exhausted guard was not visible as quarantined in list --json"
  exit 1
fi
bless guard clear-quarantine --id "$quarantine_id" >/dev/null
echo "[Smoke] v3: quarantine clear confirmed guard_id=$quarantine_id"
echo "[Smoke] smoke test completed"
