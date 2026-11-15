@echo off
REM ============================================================================
REM SecureVault - Double-Click Interactive Menu Launcher for Windows
REM ============================================================================
setlocal
cd /d "%~dp0"

where bash >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] 'bash' was not found in your Windows PATH.
    echo Please install Git for Windows (Git Bash) or WSL.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

bash "%~dp0vault.sh"
pause
