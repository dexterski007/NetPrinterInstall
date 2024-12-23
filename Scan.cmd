@echo off
:: Check if the script is running with admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script requires administrator privileges.
    echo Elevating privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change to the script's directory
pushd %~dp0

:: Run the PowerShell script
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Clear; Set-Location '%~dp0'; .\%~n0.ps1 %*"

:: Restore the original directory
popd
