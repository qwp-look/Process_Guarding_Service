param(
    [string]$Release = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'build'),
    [int]$Port = 24563,
    [string]$Token = 'long-stability-token',
    [int]$Minutes = 30,
    [int]$PollSeconds = 5,
    [string]$ProgramDataRoot = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Invoke-Pgs {
    param([string[]]$CommandArgs)
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
    if ($code -ne 0) { throw "pgs_bless failed ($($CommandArgs -join ' ')): $text" }
    $text
}

$Release = [System.IO.Path]::GetFullPath($Release)
if (-not $ProgramDataRoot) {
    $ProgramDataRoot = Join-Path (Split-Path $Release -Parent) 'pd-long-stability'
}
$BlessExe = Join-Path $Release 'pgs_bless.exe'
$ServiceExe = Join-Path $Release 'pgs_service.exe'
foreach ($path in @($BlessExe, $ServiceExe)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "missing required binary: $path" }
}

New-Item -ItemType Directory -Force -Path $ProgramDataRoot | Out-Null
$oldProgramData = $env:ProgramData
$oldToken = $env:PGS_SERVICE_TOKEN
$svc = $null
try {
    $env:ProgramData = $ProgramDataRoot
    $env:PGS_SERVICE_TOKEN = $Token
    $svc = Start-Process -FilePath $ServiceExe -ArgumentList @('run', '--port', "$Port") `
        -WorkingDirectory $Release -WindowStyle Hidden -PassThru
    for ($i = 0; $i -lt 80; $i++) {
        try { if ((Invoke-Pgs @('ping')) -match '^OK pong') { break } } catch {}
        Start-Sleep -Milliseconds 250
    }

    $deadline = (Get-Date).AddMinutes($Minutes)
    $poll = 0
    while ((Get-Date) -lt $deadline) {
        Invoke-Pgs @('ping') | Out-Null
        Invoke-Pgs @('stats') | Out-Null
        Invoke-Pgs @('list', '--json') | Out-Null
        $poll++
        if (($poll % 12) -eq 0) {
            Write-Host "[long-stability] $poll polls ok at $(Get-Date -Format s)"
        }
        Start-Sleep -Seconds $PollSeconds
    }
    Write-Host 'LONG_STABILITY_OK'
}
finally {
    if ($svc -and -not $svc.HasExited) { Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue }
    if ($null -eq $oldProgramData) { Remove-Item Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
    if ($null -eq $oldToken) { Remove-Item Env:PGS_SERVICE_TOKEN -ErrorAction SilentlyContinue } else { $env:PGS_SERVICE_TOKEN = $oldToken }
}
