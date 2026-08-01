# P0-04 bootstrap token ACL doctor/repair smoke.
# Requires elevation: doctor audits C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt,
# which is protected to SYSTEM + Administrators.
#
# 1) Ensure a token file under ProgramData state (probe or existing)
# 2) Baseline repair-state-acl -> doctor bootstrap_token_acl ok
# 3) Grant Builtin Users read via icacls -> doctor error (non-admin-token-access-ace)
# 4) repair-state-acl -> doctor ok again
param(
    [string]$BuildDir = ""
)

$ErrorActionPreference = "Stop"

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsElevated)) {
    throw "P0-04 bootstrap token ACL smoke requires an elevated PowerShell (Administrator). Re-run as admin."
}

function Find-BuildDir {
    param([string]$Hint)
    if ($Hint -and (Test-Path (Join-Path $Hint "pgs_bless.exe"))) { return (Resolve-Path $Hint).Path }
    foreach ($c in @("build_acl", "build_p0_03_ctest", "build_verify", "build", "build_acl_review")) {
        $p = Join-Path (Split-Path $PSScriptRoot -Parent) $c
        if (Test-Path (Join-Path $p "pgs_bless.exe")) { return (Resolve-Path $p).Path }
    }
    throw "Could not find pgs_bless.exe under build*/. Pass -BuildDir."
}

$root = Find-BuildDir -Hint $BuildDir
$bless = Join-Path $root "pgs_bless.exe"

$programData = $env:ProgramData
if (-not $programData) { $programData = "C:\ProgramData" }
$stateDir = Join-Path $programData "ProcessGuard\state"
$tokenPath = Join-Path $stateDir "pgs_initial_token.txt"

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

$createdProbe = $false
$previousContent = $null
$hadPrevious = Test-Path -LiteralPath $tokenPath
if ($hadPrevious) {
    try {
        $previousContent = [System.IO.File]::ReadAllBytes($tokenPath)
    } catch {
        # Existing token may still be readable after repair; keep path, no restore bytes.
        Write-Host "[TOKEN-ACL] warning: could not backup existing token bytes: $($_.Exception.Message)"
        $previousContent = $null
    }
} else {
    # Disposable probe content — not a live service token.
    Set-Content -LiteralPath $tokenPath -Value "pgs-bootstrap-token-acl-probe" -Encoding Ascii -NoNewline
    $createdProbe = $true
}

Write-Host "[TOKEN-ACL] build=$root token=$tokenPath createdProbe=$createdProbe elevated=True"

function Invoke-DoctorTokenAcl {
    $json = & $bless doctor --json 2>$null | Out-String
    if ($json -notmatch '"id":"bootstrap_token_acl"') {
        throw "doctor missing bootstrap_token_acl: $json"
    }
    return $json
}

function Assert-TokenAclStatus {
    param([string]$Json, [string]$Expected, [string]$Context)
    $pattern = '"id":"bootstrap_token_acl","status":"' + $Expected + '"'
    if ($Json -notmatch $pattern) {
        throw "$Context : expected bootstrap_token_acl status=$Expected : $Json"
    }
}

try {
    # Baseline repair so the token file starts clean.
    $repairOut = & $bless doctor repair-state-acl --json 2>&1 | Out-String
    Write-Host "[TOKEN-ACL] repair baseline: $repairOut"
    if ($LASTEXITCODE -ne 0) { throw "repair-state-acl baseline failed: $repairOut" }
    if ($repairOut -notmatch 'bootstrap_token_present=1' -or $repairOut -notmatch 'bootstrap_token_audit_ok=1') {
        throw "repair-state-acl baseline missing token fields: $repairOut"
    }

    $before = Invoke-DoctorTokenAcl
    Assert-TokenAclStatus -Json $before -Expected "ok" -Context "baseline"
    if ($before -notmatch 'reason=ok' -or $before -notmatch 'present=1') {
        throw "baseline doctor message missing present/reason ok: $before"
    }
    Write-Host "[TOKEN-ACL] baseline ok"

    # Grant Builtin Users read (token leakage). S-1-5-32-545 = BUILTIN\Users.
    $icaclsOut = & icacls.exe $tokenPath /grant "*S-1-5-32-545:(R)" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "icacls grant Users:(R) failed: $icaclsOut"
    }
    Write-Host "[TOKEN-ACL] granted BUILTIN\Users:(R) on token file"

    $broken = Invoke-DoctorTokenAcl
    Assert-TokenAclStatus -Json $broken -Expected "error" -Context "after Users read"
    if ($broken -notmatch 'non-admin-token-access-ace') {
        throw "expected reason non-admin-token-access-ace after Users read: $broken"
    }
    Write-Host "[TOKEN-ACL] doctor detected insecure token ACL"

    $repairOut2 = & $bless doctor repair-state-acl --json 2>&1 | Out-String
    Write-Host "[TOKEN-ACL] repair restore: $repairOut2"
    if ($LASTEXITCODE -ne 0) { throw "repair-state-acl restore failed: $repairOut2" }
    if ($repairOut2 -notmatch 'bootstrap_token_repaired=1' -or $repairOut2 -notmatch 'bootstrap_token_audit_ok=1') {
        throw "repair-state-acl restore missing success fields: $repairOut2"
    }

    $fixed = Invoke-DoctorTokenAcl
    Assert-TokenAclStatus -Json $fixed -Expected "ok" -Context "after repair"
    if ($fixed -notmatch 'reason=ok') {
        throw "after repair doctor reason not ok: $fixed"
    }
    Write-Host "[TOKEN-ACL] repair restored ok"
    Write-Host "[TOKEN-ACL] PASS"
}
finally {
    if ($createdProbe -and (Test-Path -LiteralPath $tokenPath)) {
        Remove-Item -LiteralPath $tokenPath -Force -ErrorAction SilentlyContinue
    } elseif ($hadPrevious -and $null -ne $previousContent) {
        # Best-effort restore original bytes; ACL left secured by repair above.
        try {
            [System.IO.File]::WriteAllBytes($tokenPath, $previousContent)
            & $bless doctor repair-state-acl --json | Out-Null
        } catch {
            Write-Host "[TOKEN-ACL] warning: could not restore previous token bytes: $($_.Exception.Message)"
        }
    }
}
