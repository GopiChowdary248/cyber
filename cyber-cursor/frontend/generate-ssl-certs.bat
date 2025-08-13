@echo off
REM Generate self-signed SSL certificates for frontend development
REM This script creates certificates that will work with localhost

echo Generating self-signed SSL certificates for frontend development...

REM Create ssl directory if it doesn't exist
if not exist "ssl" mkdir ssl

REM Generate private key
echo Generating private key...
openssl genrsa -out ssl/key.pem 2048

REM Generate certificate signing request
echo Generating certificate signing request...
openssl req -new -key ssl/key.pem -out ssl/cert.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

REM Generate self-signed certificate
echo Generating self-signed certificate...
openssl x509 -req -in ssl/cert.csr -signkey ssl/key.pem -out ssl/cert.pem -days 365

REM Clean up CSR file
del ssl\cert.csr

echo SSL certificates generated successfully!
echo Certificate: ssl\cert.pem
echo Private Key: ssl\key.pem
echo These certificates are valid for 365 days
echo Note: You may need to accept the self-signed certificate in your browser
pause
