@echo off
rem ============================================================
rem  ARISE - remove HKCU Run persistence
rem ============================================================
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Arise" /f
echo [arise] persistence removed.
pause
