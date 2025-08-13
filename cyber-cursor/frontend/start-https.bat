@echo off
echo Starting CyberShield Frontend with HTTPS...
echo.
echo Make sure you have generated SSL certificates first using generate-ssl-certs.bat
echo.
echo Frontend will be available at: https://localhost:3000
echo Backend API URL: https://localhost:8000
echo.
pause

set HTTPS=true
set SSL_CRT_FILE=./ssl/cert.pem
set SSL_KEY_FILE=./ssl/key.pem
set REACT_APP_API_URL=https://localhost:8000
set PORT=3000

npm start
