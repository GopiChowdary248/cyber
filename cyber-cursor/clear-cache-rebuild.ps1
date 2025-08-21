# Clear Cache and Rebuild Script for CyberShield Frontend
# This script will clear all caches and rebuild the frontend to resolve API path issues

Write-Host "🧹 Clearing Cache and Rebuilding Frontend..." -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# Stop any running frontend processes
Write-Host "🛑 Stopping any running frontend processes..." -ForegroundColor Yellow
Get-Process -Name "node" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Navigate to frontend directory
Set-Location "frontend"

# Clear npm cache
Write-Host "🗑️ Clearing npm cache..." -ForegroundColor Yellow
npm cache clean --force

# Clear node_modules and package-lock.json
Write-Host "🗑️ Removing node_modules and package-lock.json..." -ForegroundColor Yellow
if (Test-Path "node_modules") {
    Remove-Item -Recurse -Force "node_modules"
}
if (Test-Path "package-lock.json") {
    Remove-Item -Force "package-lock.json"
}

# Clear build directory
Write-Host "🗑️ Clearing build directory..." -ForegroundColor Yellow
if (Test-Path "build") {
    Remove-Item -Recurse -Force "build"
}

# Clear .next directory (if using Next.js)
if (Test-Path ".next") {
    Remove-Item -Recurse -Force ".next"
}

# Clear any other cache directories
if (Test-Path ".cache") {
    Remove-Item -Recurse -Force ".cache"
}

# Reinstall dependencies
Write-Host "📦 Reinstalling dependencies..." -ForegroundColor Yellow
npm install

# Build the project
Write-Host "🔨 Building the project..." -ForegroundColor Yellow
npm run build

# Start the development server
Write-Host "🚀 Starting development server..." -ForegroundColor Green
npm start

Write-Host "✅ Cache cleared and frontend rebuilt!" -ForegroundColor Green
Write-Host "🌐 Frontend should now be running at http://localhost:3000" -ForegroundColor Green
Write-Host "📝 Check the browser console for any remaining API path errors" -ForegroundColor Cyan
