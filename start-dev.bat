@echo off
REM Batch script to start both backend and frontend development servers
REM Usage: start-dev.bat

echo Starting CAC Application Development Servers...
echo.

REM Check if .NET SDK is available
dotnet --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] .NET SDK not found. Please install .NET SDK.
    pause
    exit /b 1
)

REM Check if Node.js is available
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found. Please install Node.js.
    pause
    exit /b 1
)

echo.
echo Starting servers...
echo   Backend:  http://localhost:5000
echo   Frontend: http://localhost:4200
echo   Swagger:  http://localhost:5000/swagger
echo.
echo Press Ctrl+C to stop all servers
echo.

REM Start backend in a new window
start "CAC App Backend" cmd /k "dotnet run --project CACApp.csproj"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend (this will block)
cd ClientApp
call npm start

REM Cleanup message
echo.
echo Development servers stopped.
pause
