# CyberShield Local Development Setup

This guide explains how to run CyberShield locally with PostgreSQL in Docker and the UI/API running locally.

## Prerequisites

- Docker Desktop installed and running
- Python 3.8+ installed
- Node.js 16+ installed
- npm or yarn package manager

## Quick Start

### Option 1: Use the Startup Scripts (Recommended)

#### Windows PowerShell
```powershell
.\start-local.ps1
```

#### Windows Command Prompt
```cmd
start-local.bat
```

### Option 2: Manual Setup

#### 1. Start Database Services
```bash
# Start PostgreSQL and Redis in Docker
docker-compose -f docker-compose.db-only.yml up -d

# Wait for services to be ready (about 10-15 seconds)
```

#### 2. Start Backend API
```bash
cd backend
python main.py
```

#### 3. Start Frontend (in a new terminal)
```bash
cd frontend
npm start
```

## What Gets Started

### Database Services (Docker)
- **PostgreSQL**: Running on `localhost:5432`
  - Database: `cybershield`
  - Username: `cybershield_user`
  - Password: `cybershield_password`
- **Redis**: Running on `localhost:6379`
  - Password: `redis_password`

### Local Services
- **Backend API**: Running on `http://localhost:8000`
- **Frontend**: Running on `http://localhost:3000`

## Configuration

The backend is configured to connect to the local PostgreSQL instance. The configuration is in `backend/app/core/config.py`:

```python
DATABASE_URL: str = "postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield"
```

## Stopping Services

### Using the Scripts
- Press any key when prompted to stop database services
- Close the terminal windows for backend and frontend

### Manual Stop
```bash
# Stop database services
docker-compose -f docker-compose.db-only.yml down

# Stop backend and frontend (Ctrl+C in their respective terminals)
```

## Troubleshooting

### Database Connection Issues
1. Ensure Docker is running
2. Check if PostgreSQL container is healthy:
   ```bash
   docker ps --filter "name=cybershield-postgres"
   ```
3. Check container logs:
   ```bash
   docker logs cybershield-postgres
   ```

### Port Conflicts
If ports 5432, 6379, 8000, or 3000 are already in use:
1. Stop conflicting services
2. Or modify the ports in `docker-compose.db-only.yml`

### Frontend Build Issues
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Backend Dependencies
```bash
cd backend
pip install -r requirements.txt
```

## Development Workflow

1. **Start the environment**: Run `start-local.ps1` or `start-local.bat`
2. **Make code changes**: Edit files in `backend/` or `frontend/`
3. **Backend auto-reloads**: Changes are automatically detected
4. **Frontend auto-reloads**: React development server handles hot reloading
5. **Database persistence**: Data persists between restarts (stored in Docker volumes)

## File Structure

```
cyber-cursor/
├── docker-compose.db-only.yml    # Database services only
├── start-local.ps1              # PowerShell startup script
├── start-local.bat              # Batch startup script
├── backend/                     # Python FastAPI backend
├── frontend/                    # React frontend
└── scripts/                     # Database initialization scripts
```

## Environment Variables

The following environment variables are automatically set:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `ENVIRONMENT`: Set to "development"

## Next Steps

- Access the API documentation at: `http://localhost:8000/docs`
- Access the frontend at: `http://localhost:3000`
- Create your first user account through the API
- Explore the various security modules (SAST, DAST, RASP, etc.)
