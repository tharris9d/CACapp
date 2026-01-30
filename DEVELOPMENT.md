# Development Guide

## Quick Start

### Starting Development Servers

The easiest way to start both the backend and frontend servers is using the provided startup scripts:

**Windows PowerShell:**
```powershell
.\start-dev.ps1
```

**Windows Command Prompt:**
```cmd
start-dev.bat
```

**Linux/Mac/WSL:**
```bash
./start-dev.sh
```

**Using npm (requires `concurrently`):**
```bash
cd ClientApp
npm run start:all
```

### Manual Startup

If you prefer to run servers manually:

**Terminal 1 - Backend:**
```bash
dotnet run --project CACApp.csproj
```

**Terminal 2 - Frontend:**
```bash
cd ClientApp
npm start
```

## Proxy Configuration

The application uses an enhanced proxy configuration (`ClientApp/proxy.conf.js`) that provides:

- **Better Error Handling**: Clear error messages when the backend is unavailable
- **Request Logging**: See all proxied requests in the console
- **Timeout Handling**: 30-second timeout for slow connections
- **WebSocket Support**: Proxying for WebSocket connections

### Proxy Errors

If you see `ECONNREFUSED` errors:
1. Ensure the backend is running on `http://localhost:5000`
2. Check that port 5000 is not in use by another application
3. Verify the proxy configuration in `ClientApp/proxy.conf.js`

### Switching Back to JSON Proxy Config

If you prefer the simpler JSON format, you can:

1. Update `ClientApp/angular.json`:
   ```json
   "proxyConfig": "proxy.conf.json"
   ```

2. The existing `proxy.conf.json` file will be used instead

## Port Configuration

- **Backend API**: `http://localhost:5000` (configured in `Properties/launchSettings.json`)
- **Frontend Dev Server**: `http://localhost:4200` (configured in `ClientApp/angular.json`)
- **Swagger UI**: `http://localhost:5000/swagger`

### Changing Ports

**Backend Port:**
Edit `Properties/launchSettings.json`:
```json
"applicationUrl": "http://localhost:YOUR_PORT"
```

**Frontend Port:**
Edit `ClientApp/angular.json`:
```json
"options": {
  "port": YOUR_PORT
}
```

**Don't forget to update:**
- CORS configuration in `Program.cs`
- Proxy target in `ClientApp/proxy.conf.js` or `proxy.conf.json`

## CORS Configuration

The backend CORS policy allows requests from:
- `http://localhost:4200`
- `http://127.0.0.1:4200`
- `http://localhost:4201` (fallback)
- `http://127.0.0.1:4201` (fallback)

To add more origins, edit `Program.cs`:
```csharp
policy.WithOrigins(
    "http://localhost:4200",
    "http://your-custom-origin:port"
)
```

## Troubleshooting

### Backend Won't Start

1. Check if port 5000 is in use:
   ```powershell
   netstat -ano | findstr :5000
   ```

2. Verify .NET SDK is installed:
   ```bash
   dotnet --version
   ```

3. Check for build errors:
   ```bash
   dotnet build
   ```

### Frontend Won't Start

1. Check if port 4200 is in use:
   ```powershell
   netstat -ano | findstr :4200
   ```

2. Verify Node.js is installed:
   ```bash
   node --version
   ```

3. Reinstall dependencies:
   ```bash
   cd ClientApp
   rm -rf node_modules package-lock.json
   npm install
   ```

### Proxy Errors

1. **ECONNREFUSED**: Backend is not running
   - Solution: Start the backend server

2. **502 Bad Gateway**: Backend is running but not responding
   - Solution: Check backend logs for errors
   - Verify backend is listening on the correct port

3. **CORS Errors**: Frontend origin not allowed
   - Solution: Add your frontend URL to CORS configuration in `Program.cs`

## Development Tools

### API Documentation

Swagger UI is available at `http://localhost:5000/swagger` when running in Development mode.

### Logging

- **Backend**: Logs are written to `logs/cacapp-YYYYMMDD.log` and console
- **Frontend**: Check browser console for client-side logs
- **Proxy**: Proxy logs appear in the Angular dev server console

## Building for Production

**Backend:**
```bash
dotnet publish -c Release
```

**Frontend:**
```bash
cd ClientApp
npm run build
```

The built frontend will be in `ClientApp/dist/cac-app-client/`.
