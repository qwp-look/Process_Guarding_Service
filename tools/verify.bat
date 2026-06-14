@echo off
setlocal

chcp 65001 >nul 2>&1
set "MSYS2_BASH=C:\msys64\usr\bin\bash.exe"
set "REPO_ROOT=%~dp0.."

if not exist "%MSYS2_BASH%" (
    echo MSYS2 bash not found: %MSYS2_BASH%
    exit /b 1
)

"%MSYS2_BASH%" -lc "cd \"$(cygpath \"$REPO_ROOT\")\" && ./tools/verify_pgs.sh"
exit /b %errorlevel%
