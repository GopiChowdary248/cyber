# Generate self-signed SSL certificates for frontend development
# This script creates certificates that will work with localhost

Write-Host "Generating self-signed SSL certificates for frontend development..." -ForegroundColor Green

# Create ssl directory if it doesn't exist
if (!(Test-Path "ssl")) {
    New-Item -ItemType Directory -Path "ssl" -Force
    Write-Host "Created ssl directory" -ForegroundColor Yellow
}

# Generate private key
Write-Host "Generating private key..." -ForegroundColor Yellow
openssl genrsa -out ssl/key.pem 2048

# Generate certificate signing request
Write-Host "Generating certificate signing request..." -ForegroundColor Yellow
openssl req -new -key ssl/key.pem -out ssl/cert.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate self-signed certificate
Write-Host "Generating self-signed certificate..." -ForegroundColor Yellow
openssl x509 -req -in ssl/cert.csr -signkey ssl/key.pem -out ssl/cert.pem -days 365

# Clean up CSR file
Remove-Item ssl/cert.csr -Force

Write-Host "SSL certificates generated successfully!" -ForegroundColor Green
Write-Host "Certificate: ssl/cert.pem" -ForegroundColor Cyan
Write-Host "Private Key: ssl/key.pem" -ForegroundColor Cyan
Write-Host "These certificates are valid for 365 days" -ForegroundColor Yellow
Write-Host "Note: You may need to accept the self-signed certificate in your browser" -ForegroundColor Yellow
