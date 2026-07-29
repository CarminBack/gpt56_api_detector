@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 gpt56_monitor_wizard.py
) else (
    python gpt56_monitor_wizard.py
)

echo.
pause

