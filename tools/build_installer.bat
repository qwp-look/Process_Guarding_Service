@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
pushd "%~dp0.."

REM ===========================================================================
REM  build_installer.bat - Assemble the release tree and compile the Inno Setup
REM  installer into installer\Output\pgs_setup_<version>.exe and the portable
REM  release zip into installer\Output\pgs_release_<version>.zip. A matching
REM  SHA256SUMS.txt is generated beside the artifacts for GitHub Releases.
REM
REM  Prereqs:
REM    - MSYS2 MinGW64 + Qt6 (for tools\package_release.bat)
REM    - Inno Setup 6 at its default path (ISCC.exe)
REM ===========================================================================

REM Use the 8.3 short path here. Expanding "Program Files (x86)" inside a
REM parenthesized batch block can confuse cmd.exe because of the literal ")".
if not defined ISCC set "ISCC=C:\Progra~2\Inno Setup 6\ISCC.exe"

if not defined PGS_VERSION set "PGS_VERSION=0.1.0-beta.1"

echo [1/5] Building + assembling release tree (tools\package_release.bat)...
call tools\package_release.bat
if errorlevel 1 ( echo ERROR: package_release.bat failed & popd & exit /b 1 )

echo [2/5] Running release smoke...
if not defined PGS_SKIP_RELEASE_SMOKE (
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\release_smoke.ps1 -Release "%CD%\release" -ProgramDataRoot "%CD%\build_release\pd-release-smoke-installer" -Fresh
    if errorlevel 1 ( echo ERROR: release smoke failed & popd & exit /b 1 )
) else (
    echo release smoke skipped because PGS_SKIP_RELEASE_SMOKE is set
)

if exist "release\modules\profile\pgs_profiles.db" del /f /q "release\modules\profile\pgs_profiles.db" >nul 2>&1
if exist "release\modules\profile\pgs_profiles.db" (
    echo ERROR: runtime profile database leaked into release\modules\profile
    popd & exit /b 1
)

if not exist installer\Output mkdir installer\Output >nul 2>&1
echo [3/5] Creating portable release zip...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; $zip = Join-Path (Resolve-Path 'installer\Output').Path 'pgs_release_%PGS_VERSION%.zip'; if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }; [System.IO.Compression.ZipFile]::CreateFromDirectory((Resolve-Path 'release').Path, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $false)"
if errorlevel 1 ( echo ERROR: portable zip failed & popd & exit /b 1 )

if not exist "%ISCC%" (
    echo ERROR: Inno Setup ISCC.exe not found at: %ISCC%
    echo        Install Inno Setup 6 from https://jrsoftware.org/isdl.php
    popd & exit /b 1
)

echo [4/5] Compiling installer (installer\pgs_installer.iss)...
"%ISCC%" installer\pgs_installer.iss
if errorlevel 1 ( echo ERROR: ISCC failed & popd & exit /b 1 )

echo [5/6] Writing SHA256SUMS.txt...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $out=(Resolve-Path 'installer\Output').Path; $sha=[System.Security.Cryptography.SHA256]::Create(); try { $files=@('pgs_release_%PGS_VERSION%.zip','pgs_setup_%PGS_VERSION%.exe'); $lines=foreach($name in $files){$path=Join-Path $out $name; if(-not (Test-Path -LiteralPath $path)){throw ('missing artifact: ' + $path)}; $bytes=[System.IO.File]::ReadAllBytes($path); $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant(); ($hash + '  ' + $name)}; Set-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt') -Value $lines -Encoding ASCII } finally { $sha.Dispose() }"
if errorlevel 1 ( echo ERROR: SHA256SUMS generation failed & popd & exit /b 1 )

echo [6/6] Done. Artifacts:
dir /b installer\Output\pgs_setup_*.exe 2>nul
dir /b installer\Output\pgs_release_*.zip 2>nul
dir /b installer\Output\SHA256SUMS.txt 2>nul

popd
exit /b 0
