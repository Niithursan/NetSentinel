@echo off
echo ====================================
echo   NetSentinel - Starting Services
echo ====================================
echo.

:: Check if backend port is already in use
netstat -ano | findstr ":8000" | findstr "LISTENING" > nul
if %errorlevel% equ 0 (
    echo [!] ERROR: Port 8000 is already in use.
    echo [!] Backend may already be running, or another process is using it.
    echo [!] TIP: If you have Docker running, check if 'netsentinel-api' is active.
    echo [!] Please close the existing process/container and try again.
    pause
    exit /b
)

:: Start backend
echo [1/2] Starting Backend (FastAPI)...
cd /d "%~dp0backend"
start "NetSentinel-Backend" cmd /k "venv\Scripts\activate.bat && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

:: Start frontend
echo [2/2] Starting Frontend (Vite)...
cd /d "%~dp0frontend"
start "NetSentinel-Frontend" cmd /k "npm run dev"

echo.
echo ====================================
echo   NetSentinel is starting up!
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo ====================================
echo.
echo Close this window anytime. The services run in separate windows.
pause
