@echo off
rem Double-click to install the DranzoRMM agent. Asks for administrator rights, then runs Install-DranzoAgent.ps1 from this folder.
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-DranzoAgent.ps1"
echo.
pause
