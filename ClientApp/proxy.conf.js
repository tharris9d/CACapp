/**
 * Enhanced proxy configuration with better error handling
 * 
 * This replaces proxy.conf.json to provide more control over proxy behavior.
 * Angular's dev server supports both JSON and JS proxy configurations.
 * 
 * Features:
 * - Better error messages when backend is unavailable
 * - Request/response logging for debugging
 * - 30-second timeout to handle slow connections
 * - WebSocket support for real-time features
 * 
 * If you prefer the simpler JSON format, you can switch back to proxy.conf.json
 * by updating angular.json to use "proxyConfig": "proxy.conf.json"
 */
const PROXY_CONFIG = {
  "/api": {
    "target": "http://localhost:5000",
    "secure": false,
    "changeOrigin": true,
    "logLevel": "info",
    "timeout": 30000,
    "ws": true, // Enable WebSocket proxying
    "onError": (err, req, res) => {
      console.error('Proxy error:', err.message);
      if (!res.headersSent) {
        res.writeHead(502, {
          'Content-Type': 'application/json'
        });
        res.end(JSON.stringify({
          error: 'Backend server is not available',
          message: 'Please ensure the backend API server is running on http://localhost:5000',
          details: err.message
        }));
      }
    },
    "onProxyReq": (proxyReq, req, res) => {
      console.log(`[Proxy] ${req.method} ${req.url} -> http://localhost:5000${req.url}`);
    },
    "onProxyRes": (proxyRes, req, res) => {
      console.log(`[Proxy] ${req.method} ${req.url} -> ${proxyRes.statusCode}`);
    }
  }
};

module.exports = PROXY_CONFIG;
