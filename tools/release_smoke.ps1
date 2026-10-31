param(
    [string]$Release = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'release'),
    [string]$Zip = '',
    [string]$ProgramDataRoot = '',
    [int]$Port = 23459,
    [string]$Token = 'release-smoke-token',
    [switch]$Fresh
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Invoke-Pgs {
    param(
        [string[]]$CommandArgs,
        [switch]$AllowError
    )

    $attempts = if ($AllowError) { 1 } else { 8 }
    $text = ''
    $code = 1
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $BlessExe --token $Token --port $Port @CommandArgs 2>&1
            $code = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $oldErrorAction
        }

        $text = (($output | ForEach-Object { $_.ToString() }) -join "`n").Trim()
        if ($code -eq 0 -or $text -notmatch 'Failed to connect to PGS') {
            break
        }
        Start-Sleep -Milliseconds 300
    }

    if (-not $AllowError -and $code -ne 0) {
        throw "pgs_bless failed ($($CommandArgs -join ' ')): $text"
    }

    [pscustomobject]@{
        Code = $code
        Text = $text
    }
}

function Invoke-PgsOk {
    param([string[]]$CommandArgs)
    (Invoke-Pgs -CommandArgs $CommandArgs).Text
}

function Stop-ByName {
    param([string[]]$Names)
    foreach ($name in $Names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

$Release = [System.IO.Path]::GetFullPath($Release)
$BlessExe = $null

if ($Zip) {
    $Zip = [System.IO.Path]::GetFullPath($Zip)
    if ($Fresh -and (Test-Path -LiteralPath $Release)) {
        Remove-Item -LiteralPath $Release -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Release | Out-Null
    Expand-Archive -LiteralPath $Zip -DestinationPath $Release -Force
}

if (-not (Test-Path -LiteralPath $Release)) {
    throw "release directory not found: $Release"
}

$BlessExe = Join-Path $Release 'pgs_bless.exe'
$serviceExe = Join-Path $Release 'pgs_service.exe'
$worker = Join-Path $Release 'examples\smoke_worker.exe'
if (-not (Test-Path -LiteralPath $worker)) {
    $worker = Join-Path $Release 'smoke_worker.exe'
}
$schedPath = Join-Path $Release 'modules\sched\pgs_sched_module.dll'
$healthPath = Join-Path $Release 'modules\health\pgs_health_module.dll'
$profilePath = Join-Path $Release 'modules\profile\pgs_profile_module.dll'
$profileDb = Join-Path $Release 'modules\profile\pgs_profiles.db'
$reportPath = Join-Path $Release 'modules\report\pgs_report_module.dll'
$metricsPath = Join-Path $Release 'modules\metrics\pgs_metrics_module.dll'
$backupPath = Join-Path $Release 'modules\backup\pgs_backup_module.dll'
$eventlogPath = Join-Path $Release 'modules\eventlog\pgs_eventlog_module.dll'
$dumpPath = Join-Path $Release 'modules\dump\pgs_dump_module.dll'
$serviceGuardPath = Join-Path $Release 'modules\service_guard\pgs_service_guard_module.dll'
$fileWatchPath = Join-Path $Release 'modules\file_watch\pgs_file_watch_module.dll'
$policyPath = Join-Path $Release 'modules\policy\pgs_policy_module.dll'

foreach ($required in @($BlessExe, $serviceExe, $worker, $schedPath, $healthPath, $profilePath, $reportPath, $metricsPath, $backupPath, $eventlogPath, $dumpPath, $serviceGuardPath, $fileWatchPath, $policyPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "required release artifact missing: $required"
    }
}

if (-not $ProgramDataRoot) {
    $ProgramDataRoot = Join-Path (Split-Path $Release -Parent) 'pd-release-smoke'
}
$ProgramDataRoot = [System.IO.Path]::GetFullPath($ProgramDataRoot)
if ($Fresh -and (Test-Path -LiteralPath $ProgramDataRoot)) {
    Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ProgramDataRoot | Out-Null

$serviceLog = Join-Path (Split-Path $ProgramDataRoot -Parent) 'release_smoke_service.log'
$serviceErr = Join-Path (Split-Path $ProgramDataRoot -Parent) 'release_smoke_service.err.log'

$oldProgramData = $env:ProgramData
$oldServiceToken = $env:PGS_SERVICE_TOKEN
$serviceProc = $null
$guardPid = $null

try {
    Stop-ByName @('pgs_service', 'smoke_worker')
    Remove-Item -LiteralPath $serviceLog, $serviceErr -Force -ErrorAction SilentlyContinue

    $env:ProgramData = $ProgramDataRoot
    $env:PGS_SERVICE_TOKEN = $Token
    $serviceProc = Start-Process -FilePath $serviceExe `
        -ArgumentList @('run', '--port', "$Port") `
        -WorkingDirectory $Release `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $serviceLog `
        -RedirectStandardError $serviceErr

    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        $ping = Invoke-Pgs -CommandArgs @('ping') -AllowError
        if ($ping.Code -eq 0 -and $ping.Text -match '^OK pong') {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        $logText = Get-Content -Path $serviceLog -Raw -ErrorAction SilentlyContinue
        $errText = Get-Content -Path $serviceErr -Raw -ErrorAction SilentlyContinue
        throw "PGS did not become ready.`nstdout:`n$logText`nstderr:`n$errText"
    }
    Write-Host '[release-smoke] ping ok'

    Invoke-PgsOk @('module', 'list') | Out-Null

    $schedLoad = Invoke-PgsOk @('module', 'load', '--path', $schedPath)
    if ($schedLoad -notmatch '^OK loaded') {
        throw "unexpected sched load response: $schedLoad"
    }
    Write-Host '[release-smoke] sched load ok'

    $moduleList = Invoke-PgsOk @('module', 'list')
    if ($moduleList -notmatch 'sched') {
        throw "sched module missing after load: $moduleList"
    }

    $schedCall = Invoke-PgsOk @('module', 'call', '--name', 'sched', '--request', 'op=list')
    if ($schedCall -notmatch '^OK count=') {
        throw "sched call failed: $schedCall"
    }
    Write-Host '[release-smoke] sched call ok'

    foreach ($modulePath in @($healthPath, $profilePath, $reportPath, $metricsPath, $backupPath, $eventlogPath, $dumpPath, $serviceGuardPath, $fileWatchPath, $policyPath)) {
        $load = Invoke-PgsOk @('module', 'load', '--path', $modulePath)
        if ($load -notmatch '^OK loaded') {
            throw "unexpected module load response for ${modulePath}: $load"
        }
    }
    Write-Host '[release-smoke] bundled userland modules load ok'

    $health = Invoke-PgsOk @('health', 'summary')
    if ($health -notmatch '^OK status=') {
        throw "health summary failed: $health"
    }
    $profileSet = Invoke-PgsOk @('profile', 'set', '--name', 'release', '--max-restarts', '2')
    if ($profileSet -notmatch '^OK profile saved') {
        throw "profile set failed: $profileSet"
    }
    $profileList = Invoke-PgsOk @('profile', 'list')
    if ($profileList -notmatch 'NAME=release') {
        throw "profile list missing release profile: $profileList"
    }
    $report = Invoke-PgsOk @('report', 'snapshot', '--limit', '5')
    if ($report -notmatch '^OK mode=snapshot') {
        throw "report snapshot failed: $report"
    }
    $metrics = Invoke-PgsOk @('metrics', 'summary')
    if ($metrics -notmatch '^OK guards=') {
        throw "metrics summary failed: $metrics"
    }
    $backup = Invoke-PgsOk @('backup', 'status')
    if ($backup -notmatch '^OK data_dir_b64=') {
        throw "backup status failed: $backup"
    }
    $eventlog = Invoke-PgsOk @('eventlog', 'status')
    if ($eventlog -notmatch '^OK source=Application') {
        throw "eventlog status failed: $eventlog"
    }
    foreach ($statusCheck in @(
        @('dump', 'status'),
        @('service-guard', 'status'),
        @('file-watch', 'status'),
        @('policy-template', 'status')
    )) {
        $status = Invoke-PgsOk $statusCheck
        if ($status -notmatch '^OK') {
            throw "status check failed ($($statusCheck -join ' ')): $status"
        }
    }
    Write-Host '[release-smoke] bundled module calls ok'

    $blessStart = Invoke-PgsOk @(
        'bless-start',
        '--path', $worker,
        '--start-args', '--sleep-ms 15000',
        '--max-restarts', '1',
        '--hash', 'auto'
    )
    $match = [regex]::Match($blessStart, 'pid=([0-9]+)')
    if (-not $match.Success) {
        throw "failed to parse bless-start pid: $blessStart"
    }
    $guardPid = [int]$match.Groups[1].Value

    $get = Invoke-PgsOk @('get', '--pid', "$guardPid")
    if ($get -notmatch '^OK(\s|$)') {
        throw "get failed for pid=${guardPid}: $get"
    }

    Invoke-PgsOk @('unbless', '--pid', "$guardPid") | Out-Null
    Stop-Process -Id $guardPid -Force -ErrorAction SilentlyContinue
    $guardPid = $null
    Write-Host '[release-smoke] guard lifecycle ok'

    Write-Host 'RELEASE_SMOKE_OK'
}
finally {
    if ($guardPid) {
        Invoke-Pgs -CommandArgs @('intentional', '--pid', "$guardPid") -AllowError | Out-Null
        Stop-Process -Id $guardPid -Force -ErrorAction SilentlyContinue
    }
    if ($serviceProc) {
        Stop-Process -Id $serviceProc.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $serviceProc.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    Stop-ByName @('smoke_worker')
    Remove-Item -LiteralPath $profileDb -Force -ErrorAction SilentlyContinue

    if ($null -eq $oldProgramData) {
        Remove-Item Env:ProgramData -ErrorAction SilentlyContinue
    } else {
        $env:ProgramData = $oldProgramData
    }

    if ($null -eq $oldServiceToken) {
        Remove-Item Env:PGS_SERVICE_TOKEN -ErrorAction SilentlyContinue
    } else {
        $env:PGS_SERVICE_TOKEN = $oldServiceToken
    }

}
