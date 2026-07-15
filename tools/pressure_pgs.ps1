param(
    [string]$Release = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'build'),
    [int]$Port = 24562,
    [string]$Token = 'pressure-token',
    [int]$Iterations = 50,
    [string]$ProgramDataRoot = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Stop-ProcessSafe {
    param([int]$Id)
    if ($Id) {
        Stop-Process -Id $Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Id -Timeout 5 -ErrorAction SilentlyContinue
    }
}

function Invoke-Pgs {
    param([string[]]$CommandArgs, [switch]$AllowError)
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
    if (-not $AllowError -and $code -ne 0) {
        throw "pgs_bless failed ($($CommandArgs -join ' ')): $text"
    }
    [pscustomobject]@{ Code = $code; Text = $text }
}

$Release = [System.IO.Path]::GetFullPath($Release)
if (-not $ProgramDataRoot) {
    $ProgramDataRoot = Join-Path (Split-Path $Release -Parent) 'pd-pressure'
}
$BlessExe = Join-Path $Release 'pgs_bless.exe'
$ServiceExe = Join-Path $Release 'pgs_service.exe'
$WorkerExe = Join-Path $Release 'examples\smoke_worker.exe'
if (-not (Test-Path -LiteralPath $WorkerExe)) { $WorkerExe = Join-Path $Release 'smoke_worker.exe' }
foreach ($path in @($BlessExe, $ServiceExe, $WorkerExe)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "missing required artifact: $path" }
}

New-Item -ItemType Directory -Force -Path $ProgramDataRoot | Out-Null
$oldProgramData = $env:ProgramData
$oldToken = $env:PGS_SERVICE_TOKEN
$svc = $null
$pids = New-Object System.Collections.Generic.List[int]
try {
    $env:ProgramData = $ProgramDataRoot
    $env:PGS_SERVICE_TOKEN = $Token
    $svc = Start-Process -FilePath $ServiceExe -ArgumentList @('run', '--port', "$Port") `
        -WorkingDirectory $Release -WindowStyle Hidden -PassThru
    for ($i = 0; $i -lt 80; $i++) {
        $ping = Invoke-Pgs @('ping') -AllowError
        if ($ping.Code -eq 0 -and $ping.Text -match '^OK pong') { break }
        Start-Sleep -Milliseconds 200
    }

    for ($i = 1; $i -le $Iterations; $i++) {
        $start = (Invoke-Pgs @('bless-start', '--path', $WorkerExe, '--start-args', '--sleep-ms 120000', '--max-restarts', '1', '--restart-window', '30', '--restart-delay', '0', '--hash', 'auto')).Text
        $match = [regex]::Match($start, 'pid=([0-9]+)')
        if (-not $match.Success) { throw "failed to parse pid from: $start" }
        $guardPid = [int]$match.Groups[1].Value
        $pids.Add($guardPid)
        Invoke-Pgs @('get', '--pid', "$guardPid") | Out-Null
        if (($i % 2) -eq 0) {
            Invoke-Pgs @('unbless', '--pid', "$guardPid") | Out-Null
            Stop-ProcessSafe $guardPid
        }
        else {
            Stop-ProcessSafe $guardPid
            Start-Sleep -Milliseconds 400
        }
        if (($i % 10) -eq 0) {
            Invoke-Pgs @('stats') | Out-Null
            Invoke-Pgs @('list', '--json') | Out-Null
            Write-Host "[pressure] completed $i / $Iterations"
        }
    }
    Write-Host 'PRESSURE_OK'
}
finally {
    foreach ($guardPid in $pids) {
        Invoke-Pgs @('intentional', '--pid', "$guardPid") -AllowError | Out-Null
        Stop-ProcessSafe $guardPid
    }
    if ($svc -and -not $svc.HasExited) { Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue }
    if ($null -eq $oldProgramData) { Remove-Item Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
    if ($null -eq $oldToken) { Remove-Item Env:PGS_SERVICE_TOKEN -ErrorAction SilentlyContinue } else { $env:PGS_SERVICE_TOKEN = $oldToken }
}
