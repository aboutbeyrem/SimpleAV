@echo off
title SimpleAV - Uninstall
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\SimpleAV.ps1" -Uninstall
echo.
pause
