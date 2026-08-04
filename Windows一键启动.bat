@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where pyw >nul 2>nul
if %errorlevel% equ 0 (
    start "" pyw -3 gpt56_gui.py
) else (
    start "" pythonw gpt56_gui.py
)
