@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
pushd "%~dp0.."

REM ===========================================================================
REM  build_installer.bat - Assemble the release tree and compile the Inno Setup
REM  installer into installer\Output\pgs_setup_<version>.exe.
REM
REM  Prereqs:
REM    - MSYS2 MinGW64 + Qt6 (for tools\package_release.bat)
REM    - Inno Setup 6 at its default path (ISCC.exe)
REM ===========================================================================

set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

echo [1/3] Building + assembling release tree (tools\package_release.bat)...
call tools\package_release.bat
if errorlevel 1 ( echo ERROR: package_release.bat failed & popd & exit /b 1 )

if not exist "%ISCC%" (
    echo ERROR: Inno Setup ISCC.exe not found at: %ISCC%
    echo        Install Inno Setup 6 from https://jrsoftware.org/isdl.php
    popd & exit /b 1
)

echo [2/3] Compiling installer (installer\pgs_installer.iss)...
"%ISCC%" installer\pgs_installer.iss
if errorlevel 1 ( echo ERROR: ISCC failed & popd & exit /b 1 )

echo [3/3] Done. Installer:
dir /b installer\Output\pgs_setup_*.exe 2>nul

popd
exit /b 0
