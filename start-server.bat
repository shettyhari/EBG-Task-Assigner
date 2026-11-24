@echo off
title EBG Task Assigner Server
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
    python server.py --open
) else (
    py server.py --open
)
echo.
echo The EBG server has stopped. Close this window, or press any key to exit.
pause >nul
