@echo off
setlocal
chcp 65001 >nul 2>&1
pushd "%~dp0.."

call tools\test_core_units.bat
if errorlevel 1 (
    set "RC=%errorlevel%"
    popd
    exit /b %RC%
)

call tools\test_sched_cron.bat
set "RC=%errorlevel%"
popd
exit /b %RC%
