@echo off
rem ============================================================
rem  ARISE - OPTIONAL persistence (HKCU Run key). Run this ONLY
rem  if you want Arise to auto-start at login on this machine.
rem  This script does NOT run automatically - executing it is
rem  a deliberate action by you.
rem ============================================================
set "PYTHONW="
for /f "delims=" %%i in ('where pythonw 2^>nul') do if not defined PYTHONW set "PYTHONW=%%i"
if not defined PYTHONW (
    echo [arise] pythonw.exe not found on PATH. Cannot persist.
    pause
    exit /b 1
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Arise" /t REG_SZ /d "\"%PYTHONW%\" \"%~dp0arise.py\"" /f
echo [arise] persistence added (HKCU Run). Remove with arise_unpersist.bat
pause
