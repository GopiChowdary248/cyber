# HTTPS Setup Guide for CyberShield Frontend

This guide explains how to configure the CyberShield application to use HTTPS for the frontend and ensure proper communication with the backend and PostgreSQL.

## Overview

The application has been updated to use HTTPS instead of HTTP for the frontend. The frontend will run on `https://localhost:3000` and communicate with the backend at `https://localhost:8000`.

## Prerequisites

1. **OpenSSL**: Required to generate SSL certificates
   - Download from: https://slproweb.com/products/Win32OpenSSL.html
   - Add OpenSSL to your system PATH

2. **PostgreSQL**: Must be running and accessible
3. **Backend**: FastAPI backend must be running

## Quick Setup

### Option 1: Automated Setup (Recommended)

Run the comprehensive setup script:

```powershell
.\setup-https-frontend.ps1
```

This script will:
- Check OpenSSL availability
- Generate SSL certificates
- Update all environment files
- Check PostgreSQL and backend status
- Provide next steps

### Option 2: Manual Setup

#### Step 1: Generate SSL Certificates

```powershell
# Navigate to frontend directory
cd frontend

# Generate certificates
.\generate-ssl-certs.ps1
```

Or using batch file:
```cmd
.\generate-ssl-certs.bat
```

#### Step 2: Update Environment Files

The following files have been updated:
- `frontend/.env.local` - Frontend environment variables
- `env.local` - Root development environment
- `env.production` - Root production environment
- `frontend/package.json` - Package configuration
- `frontend/src/utils/apiClient.ts` - API client configuration

#### Step 3: Start the Application

1. **Start Backend**:
   ```bash
   cd backend
   python main.py
   ```

2. **Start Frontend with HTTPS**:
   ```powershell
   cd frontend
   .\start-https.ps1
   ```

   Or using batch file:
   ```cmd
   .\start-https.bat
   ```

## Configuration Details

### Frontend Configuration

- **URL**: `https://localhost:3000`
- **API Endpoint**: `https://localhost:8000`
- **SSL Certificates**: `frontend/ssl/cert.pem` and `frontend/ssl/key.pem`
- **Environment Variables**: Set in `frontend/.env.local`

### Backend Configuration

- **URL**: `https://localhost:8000`
- **CORS**: Updated to allow HTTPS frontend origins
- **Database**: PostgreSQL connection maintained

### Environment Variables

Key environment variables for the frontend:

```bash
REACT_APP_API_URL=https://localhost:8000
HTTPS=true
SSL_CRT_FILE=./ssl/cert.pem
SSL_KEY_FILE=./ssl/key.pem
PORT=3000
```

## Troubleshooting

### SSL Certificate Issues

1. **Browser Security Warning**: Accept the self-signed certificate
2. **Certificate Not Found**: Regenerate certificates using the scripts
3. **Port Already in Use**: Change the PORT environment variable

### Backend Connection Issues

1. **CORS Errors**: Ensure backend CORS settings include HTTPS origins
2. **Connection Refused**: Verify backend is running on port 8000
3. **Database Connection**: Check PostgreSQL service status

### Frontend Issues

1. **HTTPS Not Working**: Verify SSL certificates exist and are valid
2. **API Calls Failing**: Check `REACT_APP_API_URL` environment variable
3. **Port Conflicts**: Ensure port 3000 is available

## File Structure

```
cyber-cursor/
├── frontend/
│   ├── .env.local              # Frontend environment variables
│   ├── ssl/                    # SSL certificates
│   │   ├── cert.pem           # SSL certificate
│   │   └── key.pem            # Private key
│   ├── start-https.ps1        # PowerShell startup script
│   ├── start-https.bat        # Batch startup script
│   └── generate-ssl-certs.ps1 # Certificate generation script
├── backend/                    # Backend application
├── env.local                   # Root development environment
├── env.production             # Root production environment
└── setup-https-frontend.ps1   # Comprehensive setup script
```

## Security Notes

1. **Self-Signed Certificates**: These are for development only
2. **Production**: Use proper SSL certificates from a trusted CA
3. **Environment Variables**: Keep sensitive data in environment files
4. **CORS**: Restrict origins in production environments

## Next Steps

After setup:

1. Access the frontend at: `https://localhost:3000`
2. Backend API available at: `https://localhost:8000`
3. API documentation at: `https://localhost:8000/docs`
4. Health check at: `https://localhost:8000/health`

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Verify all prerequisites are met
3. Check service status (PostgreSQL, Backend)
4. Review environment variable configuration
5. Check browser console for errors

## Production Deployment

For production deployment:

1. Replace self-signed certificates with proper SSL certificates
2. Update environment variables for production
3. Configure proper CORS origins
4. Use environment-specific configuration files
5. Enable proper security headers and HTTPS enforcement
