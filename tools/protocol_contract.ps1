param(
    [string]$Release = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'build'),
    [int]$Port = 24561,
    [string]$Token = 'protocol-contract-token',
    [string]$ProgramDataRoot = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Stop-ProcessSafe {
    param([System.Diagnostics.Process]$Process)
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

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
    if ($code -ne 0) {
        throw "pgs_bless failed ($($CommandArgs -join ' ')): $text"
    }
    $text
}

$Release = [System.IO.Path]::GetFullPath($Release)
if (-not $ProgramDataRoot) {
    $ProgramDataRoot = Join-Path (Split-Path $Release -Parent) 'pd-protocol-contract'
}
$BlessExe = Join-Path $Release 'pgs_bless.exe'
$ServiceExe = Join-Path $Release 'pgs_service.exe'
foreach ($path in @($BlessExe, $ServiceExe)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing required binary: $path"
    }
}

New-Item -ItemType Directory -Force -Path $ProgramDataRoot | Out-Null
$oldProgramData = $env:ProgramData
$oldToken = $env:PGS_SERVICE_TOKEN
$proc = $null
try {
    $env:ProgramData = $ProgramDataRoot
    $env:PGS_SERVICE_TOKEN = $Token
    $proc = Start-Process -FilePath $ServiceExe -ArgumentList @('run', '--port', "$Port") `
        -WorkingDirectory $Release -WindowStyle Hidden -PassThru

    for ($i = 0; $i -lt 60; $i++) {
        try {
            if ((Invoke-Pgs @('ping')) -match '^OK pong') { break }
        }
        catch {
            if ($i -eq 59) { throw }
            Start-Sleep -Milliseconds 250
        }
    }

    if ((Invoke-Pgs @('version')) -notmatch '^OK\s+protocol=3\s+min=2') {
        throw 'version contract mismatch'
    }
    if ((Invoke-Pgs @('stats')) -notmatch '^OK\s+guards=\d+\s+active=\d+.*protocol=3') {
        throw 'stats contract mismatch'
    }
    $json = Invoke-Pgs @('list', '--json')
    $arr = $json | ConvertFrom-Json
    if ($null -eq $arr) {
        throw 'list --json did not produce JSON'
    }
    Write-Host 'PROTOCOL_CONTRACT_OK'
}
finally {
    Stop-ProcessSafe $proc
    if ($null -eq $oldProgramData) { Remove-Item Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
    if ($null -eq $oldToken) { Remove-Item Env:PGS_SERVICE_TOKEN -ErrorAction SilentlyContinue } else { $env:PGS_SERVICE_TOKEN = $oldToken }
}
