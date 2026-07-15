@echo off
setlocal

chcp 65001 >nul 2>&1
if not defined MSYS2_ROOT set "MSYS2_ROOT=C:\msys64"
if not defined MSYS2_BASH set "MSYS2_BASH=%MSYS2_ROOT%\usr\bin\bash.exe"
set "REPO_ROOT=%~dp0.."
if not defined PGS_BUILD_DIR set "PGS_BUILD_DIR=build_verify"
set "PGS_TMP=%REPO_ROOT%\%PGS_BUILD_DIR%\tmp"
set "PGS_HOME=%REPO_ROOT%\%PGS_BUILD_DIR%\home"

if not exist "%MSYS2_BASH%" (
    echo MSYS2 bash not found: %MSYS2_BASH%
    echo Set MSYS2_ROOT or MSYS2_BASH to your MSYS2 installation.
    exit /b 1
)

if not exist "%PGS_TMP%" mkdir "%PGS_TMP%"
if not exist "%PGS_HOME%" mkdir "%PGS_HOME%"
set "TMP=%PGS_TMP%"
set "TEMP=%PGS_TMP%"
set "TMPDIR=%PGS_TMP%"
set "HOME=%PGS_HOME%"

"%MSYS2_BASH%" -lc "cd \"$(cygpath \"$REPO_ROOT\")\" && export HOME=\"$(cygpath \"$HOME\")\" TMPDIR=\"$(cygpath \"$TMPDIR\")\" TEMP=\"$TMPDIR\" TMP=\"$TMPDIR\" && ./tools/verify_pgs.sh"
exit /b %errorlevel%
