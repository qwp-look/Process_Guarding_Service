<#
.SYNOPSIS
  WindowsApps (UWP) activation guard end-to-end verification.

.DESCRIPTION
  Starts pgs_service.exe in console `run` mode, launches a UWP target
  (Microsoft Edge by default), blesses it as --winapp --aumid, kills it,
  and asserts PGS revives it via IApplicationActivationManager::ActivateApplication.
  Must be run from an elevated PowerShell in the user's interactive session
  (the winapp activation path needs the user's session token).

.PARAMETER Here
  Directory containing pgs_service.exe / pgs_bless.exe (and their MinGW DLLs).
  Default: script directory.

.PARAMETER Token
  Auth token for the PGS service. Default: pgsvm.

.PARAMETER Aumid
  AUMID of the UWP to guard. Default: Microsoft Edge stable.

.EXAMPLE
  pwsh -File tools\verify_winapp.ps1 -Here C:\Users\qwq\Desktop\pgs_live
#>
[CmdletBinding()]
param(
    [string]$Here = $PSScriptRoot,
    [string]$Token = "pgsvm",
    [string]$Aumid = "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App"
)
$ErrorActionPreference = "Continue"
Set-Location $Here

"=== 0) cleanup ==="
Get-Process pgs_service,pgs_bless,msedge -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Remove-Item "$env:ProgramData\ProcessGuard\state\pgs_guard_state.db","$env:ProgramData\ProcessGuard\state\pgs_initial_token.txt" -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

"=== 1) start pgs_service ==="
$svc = Start-Process "$Here\pgs_service.exe" -ArgumentList "run --token $Token" -WorkingDirectory $Here -PassThru -WindowStyle Hidden -RedirectStandardOutput "$Here\svc.log" -RedirectStandardError "$Here\svc.err"
"SERVICE_PID=$($svc.Id)"
$ready = 0
for ($i = 0; $i -lt 30; $i++) {
    $r = & "$Here\pgs_bless.exe" ping --token $Token 2>$null
    if ($r -match "pong") { $ready = 1; break }
    Start-Sleep -Milliseconds 300
}
"READY=$ready tries=$($i+1)"
if ($ready -ne 1) {
    "ABORT no ping"; Get-Content "$Here\svc.err" -ErrorAction SilentlyContinue | Out-String
    Get-Content "$Here\svc.log" -ErrorAction SilentlyContinue | Out-String
    Stop-Process -Id $svc.Id -Force; exit 1
}

"=== 2) launch UWP target ==="
Start-Process msedge.exe -ArgumentList "--new-window about:blank" | Out-Null
Start-Sleep -Milliseconds 3000
$edge = Get-Process msedge -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
if (-not $edge) { "ABORT target did not start"; Stop-Process -Id $svc.Id -Force; exit 1 }
"EDGE_PID=$($edge.Id) Session=$($edge.SessionId)"

"=== 3) bless winapp ==="
$bl = & "$Here\pgs_bless.exe" bless --pid $edge.Id --winapp --aumid $Aumid --hash none --token $Token 2>&1
"BLESS_OUT=$bl"
Start-Sleep -Milliseconds 1200

"=== 4) list ==="
& "$Here\pgs_bless.exe" list --token $Token 2>&1 | ForEach-Object { "LIST: $_" }

"=== 5) kill target ==="
Stop-Process -Id $edge.Id -Force
"KILLED_at=$(Get-Date -Format HH:mm:ss.fff)"
Start-Sleep -Milliseconds 1500

"=== 6) wait restart (max 15s) ==="
$sw = [Diagnostics.Stopwatch]::StartNew(); $restarted = $false; $new = 0; $newSession = -1
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    $c = Get-Process msedge -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
    if ($c) { $restarted = $true; $new = $c.Id; $newSession = $c.SessionId; break }
}
$sw.Stop()
"RESTARTED=$restarted NEW_PID=$new NEW_SESSION=$newSession DELAY_SEC=$([math]::Round($sw.Elapsed.TotalSeconds,2))"

"=== 7) cleanup ==="
if ($new) { & "$Here\pgs_bless.exe" unregister --pid $new --token $Token 2>&1 | Out-Null }
Get-Process msedge -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
try { Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue } catch {}

"=== 8) svc log (key lines) ==="
Get-Content "$Here\svc.log" -ErrorAction SilentlyContinue | Where-Object { $_ -match "winapp|restart|Activate|registered|exit|dead|guard" } | ForEach-Object { "LOG: $_" }
"=== 9) svc err ==="
Get-Content "$Here\svc.err" -ErrorAction SilentlyContinue | Out-String

if (-not $restarted) { "RESULT=FAIL"; exit 2 }
"RESULT=PASS"
"=== DONE ==="