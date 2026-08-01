# P0-03 modules ACL negative smoke (elevated recommended).
# 1) Baseline repair -> doctor recursive ok
# 2) Grant Builtin Users write on a nested path -> doctor error
# 3) module load must fail closed (hard fail if service accepts the load)
# 4) repair-modules-acl -> doctor ok again
param(
    [string]$BuildDir = "",
    [string]$HostName = "127.0.0.1",
    [int]$Port = 12345,
    [switch]$SkipLoad
)

$ErrorActionPreference = "Stop"

function Find-BuildDir {
    param([string]$Hint)
    if ($Hint -and (Test-Path (Join-Path $Hint "pgs_bless.exe"))) { return (Resolve-Path $Hint).Path }
    foreach ($c in @("build_acl", "build_p0_03_ctest", "build_verify", "build")) {
        $p = Join-Path (Split-Path $PSScriptRoot -Parent) $c
        if (Test-Path (Join-Path $p "pgs_bless.exe")) { return (Resolve-Path $p).Path }
    }
    throw "Could not find pgs_bless.exe under build*/. Pass -BuildDir."
}

$root = Find-BuildDir -Hint $BuildDir
$bless = Join-Path $root "pgs_bless.exe"
$modules = Join-Path $root "modules"
if (-not (Test-Path $modules)) { throw "modules dir missing: $modules" }

# Prefer a real nested path under a module directory for recursive coverage.
$nestedDir = Join-Path $modules "sched\nested_acl_probe"
New-Item -ItemType Directory -Path $nestedDir -Force | Out-Null
$nestedDll = Join-Path $nestedDir "evil.dll"
Set-Content -Path $nestedDll -Value "MZ-nested-acl-probe" -Encoding Byte -ErrorAction SilentlyContinue
if (-not (Test-Path $nestedDll)) {
    [System.IO.File]::WriteAllBytes($nestedDll, [byte[]](0x4D, 0x5A, 0x2D, 0x6E))
}

$dll = Get-ChildItem -Path $modules -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "pgs_*_module.dll" } |
    Select-Object -First 1
if (-not $dll) { throw "No bundled module DLL under $modules" }

Write-Host "[ACL] build=$root nested=$nestedDll moduleDll=$($dll.FullName)"

function Invoke-DoctorRecursive {
    $json = & $bless doctor --json 2>$null | Out-String
    if ($json -notmatch '"id":"modules_acl_recursive"') { throw "doctor missing modules_acl_recursive: $json" }
    return $json
}

function Assert-RecursiveStatus {
    param([string]$Json, [string]$Expected, [string]$Context)
    $pattern = '"id":"modules_acl_recursive","status":"' + $Expected + '"'
    if ($Json -notmatch $pattern) {
        throw "$Context : expected modules_acl_recursive status=$Expected : $Json"
    }
}

# Baseline repair so the tree starts clean (explicit repair path only).
& $bless doctor repair-modules-acl --json | Out-Host
if ($LASTEXITCODE -ne 0) { throw "repair-modules-acl baseline failed" }
$before = Invoke-DoctorRecursive
Assert-RecursiveStatus -Json $before -Expected "ok" -Context "baseline"
Write-Host "[ACL] baseline ok"

# Grant Builtin Users write via icacls (stable non-admin write ACE for doctor detection).
# S-1-5-32-545 = BUILTIN\Users. Prefer /grant over Set-Acl SDDL rewrites.
$icaclsOut = & icacls.exe $nestedDll /grant "*S-1-5-32-545:(W)" 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "icacls grant Users:(W) failed: $icaclsOut"
}
$aclCheck = & icacls.exe $nestedDll 2>&1 | Out-String
if ($aclCheck -notmatch 'BUILTIN\\Users:\(W\)' -and $aclCheck -notmatch 'Users:\(W\)' -and $aclCheck -notmatch '\(W\)') {
    Write-Host "[ACL] icacls output after grant: $aclCheck"
}
Write-Host "[ACL] granted BUILTIN\Users:(W) on nested evil.dll"

$broken = Invoke-DoctorRecursive
Assert-RecursiveStatus -Json $broken -Expected "error" -Context "after nested Users write"
if ($broken -notmatch 'bad_count=[1-9]') {
    throw "expected bad_count>0 after nested Users write: $broken"
}
if ($broken -notmatch 'first_bad_path_b64=') {
    throw "expected first_bad_path_b64 in doctor output: $broken"
}
Write-Host "[ACL] doctor detected insecure nested ACL"

if (-not $SkipLoad) {
    # module load must fail-closed when service is reachable without permissive mode.
    $loadArgs = @('module', 'load', '--path', $dll.FullName, '--host', $HostName, '--port', "$Port")
    $loadOut = & $bless @loadArgs 2>&1 | Out-String
    Write-Host "[ACL] module load output: $loadOut"
    if ($loadOut -match 'could not connect|Failed to connect|connection refused|No connection') {
        throw "pgs_service not reachable for module load fail-closed check. Start service without --allow-all-modules, then re-run. output=$loadOut"
    }
    if ($loadOut -match 'OK loaded' -or ($loadOut -match '(?m)^OK\b' -and $loadOut -notmatch 'acl-insecure')) {
        throw "module load succeeded while modules ACL is insecure (fail-closed broken): $loadOut"
    }
    if ($loadOut -notmatch 'acl-insecure') {
        throw "module load did not fail closed with module.acl-insecure: $loadOut"
    }
    Write-Host "[ACL] module load correctly refused"
}

& $bless doctor repair-modules-acl --json | Out-Host
if ($LASTEXITCODE -ne 0) { throw "repair-modules-acl restore failed" }
$fixed = Invoke-DoctorRecursive
Assert-RecursiveStatus -Json $fixed -Expected "ok" -Context "after repair"

# Cleanup probe artifact so release trees stay clean.
Remove-Item -LiteralPath $nestedDir -Recurse -Force -ErrorAction SilentlyContinue
# Re-repair after cleanup so removed-path gaps are not left insecure.
& $bless doctor repair-modules-acl --json | Out-Null

Write-Host "[ACL] repair restored ok"
Write-Host "[ACL] PASS"
