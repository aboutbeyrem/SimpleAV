@echo off
title SimpleAV - Install
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\SimpleAV.ps1" -Install
echo.
pause
