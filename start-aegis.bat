@echo off
rem Starts AEGIS locally on Windows: backend (port 8000) and frontend (port 5173),
rem each in its own window, then opens the browser. Close both windows to stop.
setlocal
set "ROOT=%~dp0"
title AEGIS launcher

where python >nul 2>&1 || (echo Python 3.12+ is not installed or not on PATH. & goto :fail)
where npm >nul 2>&1 || (
    if exist "C:\Program Files\nodejs\npm.cmd" (
        set "PATH=C:\Program Files\nodejs;%PATH%"
    ) else (
        echo Node.js 22.12+ is not installed or not on PATH. & goto :fail
    )
)

netstat -ano | findstr /r /c:":8000 .*LISTENING" >nul && (
    echo Port 8000 is already in use, probably by an AEGIS backend that is still running.
    echo Close its window, or find it with: netstat -ano ^| findstr :8000
    goto :fail
)
netstat -ano | findstr /r /c:":5173 .*LISTENING" >nul && (
    echo Port 5173 is already in use, probably by an AEGIS frontend that is still running.
    goto :fail
)

rem --- First run: install dependencies ---
if not exist "%ROOT%backend\.venv\Scripts\python.exe" (
    echo Creating the Python environment ^(first run only^)...
    python -m venv "%ROOT%backend\.venv" || goto :fail
    "%ROOT%backend\.venv\Scripts\python.exe" -m pip install -r "%ROOT%backend\requirements.txt" || goto :fail
)
if not exist "%ROOT%frontend\node_modules" (
    echo Installing frontend packages ^(first run only^)...
    pushd "%ROOT%frontend"
    call npm ci || (popd & goto :fail)
    popd
)

rem --- Database schema ---
pushd "%ROOT%backend"
".venv\Scripts\python.exe" -m alembic upgrade head || (popd & goto :fail)
popd

rem --- Start both servers ---
start "AEGIS backend (close to stop)" /d "%ROOT%backend" cmd /k ".venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000"
start "AEGIS frontend (close to stop)" /d "%ROOT%frontend" cmd /k "npm run dev"

echo Waiting for AEGIS to start...
for /l %%i in (1,1,60) do (
    curl -s -o nul http://127.0.0.1:8000/api/v1/health/live && curl -s -o nul http://localhost:5173 && goto :ready
    "%SystemRoot%System32	imeout.exe" /t 1 /nobreak >nul
)
echo AEGIS did not start within 60 seconds. Check the backend and frontend windows.
goto :fail

:ready
echo AEGIS is running: http://localhost:5173
if not defined AEGIS_NO_BROWSER start "" http://localhost:5173
exit /b 0

:fail
echo.
pause
exit /b 1
