#!/bin/bash
# Bash script to start both backend and frontend development servers
# Usage: ./start-dev.sh

echo "Starting CAC Application Development Servers..."
echo ""

# Check if .NET SDK is available
if ! command -v dotnet &> /dev/null; then
    echo "✗ .NET SDK not found. Please install .NET SDK."
    exit 1
fi
echo "✓ .NET SDK found: $(dotnet --version)"

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "✗ Node.js not found. Please install Node.js."
    exit 1
fi
echo "✓ Node.js found: $(node --version)"

echo ""
echo "Starting servers..."
echo "  Backend:  http://localhost:5000"
echo "  Frontend: http://localhost:4200"
echo "  Swagger:  http://localhost:5000/swagger"
echo ""
echo "Press Ctrl+C to stop all servers"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping servers..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "Development servers stopped."
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup SIGINT SIGTERM

# Start backend server in background
dotnet run --project CACApp.csproj &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Start frontend server in background
cd ClientApp
npm start &
FRONTEND_PID=$!

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID
