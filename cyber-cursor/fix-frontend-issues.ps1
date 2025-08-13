# Fix Frontend Compilation Issues Script
Write-Host "🔧 Fixing Frontend Compilation Issues..." -ForegroundColor Green

# Go to frontend directory
Set-Location frontend

# Run ESLint with auto-fix
Write-Host "Running ESLint auto-fix..." -ForegroundColor Yellow
npm run lint:fix

# Install any missing dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
npm install

# Start the frontend
Write-Host "Starting frontend..." -ForegroundColor Green
npm start
