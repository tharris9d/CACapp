# PowerShell script to start both backend and frontend development servers
# Usage: .\start-dev.ps1

Write-Host "Starting CAC Application Development Servers..." -ForegroundColor Cyan
Write-Host ""

# Check if .NET SDK is available
try {
    $dotnetVersion = dotnet --version
    Write-Host "✓ .NET SDK found: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ .NET SDK not found. Please install .NET SDK." -ForegroundColor Red
    exit 1
}

# Check if Node.js is available
try {
    $nodeVersion = node --version
    Write-Host "✓ Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Node.js not found. Please install Node.js." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Starting servers..." -ForegroundColor Yellow
Write-Host "  Backend:  http://localhost:5000" -ForegroundColor Blue
Write-Host "  Frontend: http://localhost:4200" -ForegroundColor Green
Write-Host "  Swagger:  http://localhost:5000/swagger" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop all servers" -ForegroundColor Yellow
Write-Host ""

# Start backend server in background
$backendJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    dotnet run --project CACApp.csproj
}

# Start frontend server
Set-Location ClientApp
npm run start

# Cleanup: Stop backend job when frontend stops
Stop-Job $backendJob
Remove-Job $backendJob

Write-Host ""
Write-Host "Development servers stopped." -ForegroundColor Yellow
