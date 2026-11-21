@echo off
rem ============================================================
rem  ARISE keylogger - stop. Creates the stop-flag file; the
rem  running instance detects it and unhooks cleanly.
rem ============================================================
if exist "%~dp0arise.stop" del "%~dp0arise.stop" >nul 2>nul
type nul > "%~dp0arise.stop"
echo [arise] stop flag created at "%~dp0arise.stop"
echo [arise] the running instance will exit within ~1 second.
