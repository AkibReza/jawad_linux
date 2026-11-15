@echo off
setlocal
where bash >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] 'bash' was not found in your Windows PATH.
    echo Please install Git for Windows or WSL.
    pause
    exit /b 1
)

bash "%~dp0vault.sh" %*
