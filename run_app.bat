@echo off
REM =========================================================================
REM DocSentry Application Runner
REM Activates virtual environment and starts FastAPI local production server
REM =========================================================================

echo.
echo =========================================================================
echo                DocSentry: PDF Malware Detection Engine                   
echo       Explainable, Uncertainty-Aware Static Analysis (Local Only)        
echo =========================================================================
echo.

IF NOT EXIST ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found in .venv.
    echo Please create the virtual environment first.
    pause
    exit /b 1
)

echo [*] Activating virtual environment (.venv)...
call .venv\Scripts\activate.bat

echo.
echo [*] DocSentry Web Application available at:
echo        http://127.0.0.1:8000/
echo        http://localhost:8000/
echo.
echo [*] API Documentation:
echo        http://127.0.0.1:8000/docs
echo.
echo Press Ctrl+C to stop the server.
echo.

uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info
