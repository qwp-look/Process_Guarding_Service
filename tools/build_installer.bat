@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
pushd "%~dp0.."

REM ===========================================================================
REM  build_installer.bat - Assemble the release tree and compile the Inno Setup
REM  installer into installer\Output\pgs_setup_<version>.exe and the portable
REM  release zip into installer\Output\pgs_release_<version>.zip.
REM
REM  Prereqs:
REM    - MSYS2 MinGW64 + Qt6 (for tools\package_release.bat)
REM    - Inno Setup 6 at its default path (ISCC.exe)
REM ===========================================================================

REM Use the 8.3 short path here. Expanding "Program Files (x86)" inside a
REM parenthesized batch block can confuse cmd.exe because of the literal ")".
if not defined ISCC set "ISCC=C:\Progra~2\Inno Setup 6\ISCC.exe"

set "PGS_VERSION=3.1.0"

echo [1/4] Building + assembling release tree (tools\package_release.bat)...
call tools\package_release.bat
if errorlevel 1 ( echo ERROR: package_release.bat failed & popd & exit /b 1 )

if not exist installer\Output mkdir installer\Output >nul 2>&1
echo [2/4] Creating portable release zip...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'release\*' -DestinationPath 'installer\Output\pgs_release_%PGS_VERSION%.zip' -Force"
if errorlevel 1 ( echo ERROR: portable zip failed & popd & exit /b 1 )

if not exist "%ISCC%" (
    echo ERROR: Inno Setup ISCC.exe not found at: %ISCC%
    echo        Install Inno Setup 6 from https://jrsoftware.org/isdl.php
    popd & exit /b 1
)

echo [3/4] Compiling installer (installer\pgs_installer.iss)...
"%ISCC%" installer\pgs_installer.iss
if errorlevel 1 ( echo ERROR: ISCC failed & popd & exit /b 1 )

echo [4/4] Done. Artifacts:
dir /b installer\Output\pgs_setup_*.exe 2>nul
dir /b installer\Output\pgs_release_*.zip 2>nul

popd
exit /b 0
