@echo off
echo Starting CyberShield Frontend with HTTPS (Simple Method)...
echo.
echo Frontend will be available at: https://localhost:3000
echo Backend API URL: https://localhost:8000
echo.
echo Note: This uses React's built-in HTTPS with self-signed certificates
echo You may need to accept security warnings in your browser
echo.
pause

set HTTPS=true
set REACT_APP_API_URL=https://localhost:8000
set PORT=3000

echo Environment variables set:
echo HTTPS: %HTTPS%
echo REACT_APP_API_URL: %REACT_APP_API_URL%
echo PORT: %PORT%
echo.

echo Starting npm start...
npm start
