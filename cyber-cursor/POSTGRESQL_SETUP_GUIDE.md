# PostgreSQL Setup Guide for CyberShield

This guide will help you set up PostgreSQL for your CyberShield Security Platform and resolve the database session issues.

## Prerequisites

- Docker Desktop installed and running
- PowerShell (for Windows users)
- Basic understanding of Docker and databases

## Quick Setup

### 1. Start PostgreSQL with Docker

Run the provided PowerShell script to set up PostgreSQL:

```powershell
.\scripts\setup-postgresql.ps1
```

This script will:
- Create a PostgreSQL container
- Initialize the database schema
- Test the connection
- Set up proper permissions

### 2. Alternative Manual Setup

If you prefer to set up manually:

```bash
# Create Docker network
docker network create cybershield-network

# Start PostgreSQL
docker run -d \
  --name cybershield-postgres \
  --network cybershield-network \
  -e POSTGRES_DB=cybershield \
  -e POSTGRES_USER=cybershield_user \
  -e POSTGRES_PASSWORD=cybershield_password \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  postgres:15-alpine

# Wait for PostgreSQL to be ready
docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield
```

### 3. Initialize Database Schema

```bash
# Copy the initialization script to the container
docker cp scripts/init-postgresql.sql cybershield-postgres:/tmp/

# Run the initialization script
docker exec -i cybershield-postgres psql -U cybershield_user -d cybershield -f /tmp/init-postgresql.sql
```

## Environment Configuration

### 1. Create Environment File

Copy the provided environment template:

```bash
cp env.local .env
```

### 2. Update Database URL

Ensure your `.env` file contains:

```env
DATABASE_URL=postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield
```

### 3. Verify Configuration

The database configuration should match:
- **Host**: localhost
- **Port**: 5432
- **Database**: cybershield
- **Username**: cybershield_user
- **Password**: cybershield_password

## Database Connection Details

| Setting | Value |
|---------|-------|
| Host | localhost |
| Port | 5432 |
| Database | cybershield |
| Username | cybershield_user |
| Password | cybershield_password |
| Connection String | `postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield` |

## Testing the Connection

### 1. Test with Docker

```bash
docker exec -it cybershield-postgres psql -U cybershield_user -d cybershield -c "SELECT version();"
```

### 2. Test with Python

```python
import asyncio
import asyncpg

async def test_connection():
    try:
        conn = await asyncpg.connect(
            user='cybershield_user',
            password='cybershield_password',
            database='cybershield',
            host='localhost',
            port=5432
        )
        print("✓ PostgreSQL connection successful")
        await conn.close()
    except Exception as e:
        print(f"✗ Connection failed: {e}")

asyncio.run(test_connection())
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check container logs
docker logs cybershield-postgres
```

#### 2. Authentication Failed
```bash
# Reset PostgreSQL password
docker exec -it cybershield-postgres psql -U postgres -c "ALTER USER cybershield_user PASSWORD 'cybershield_password';"
```

#### 3. Database Does Not Exist
```bash
# Create database manually
docker exec -it cybershield-postgres psql -U postgres -c "CREATE DATABASE cybershield OWNER cybershield_user;"
```

#### 4. Permission Denied
```bash
# Grant permissions
docker exec -it cybershield-postgres psql -U postgres -d cybershield -c "GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;"
```

### Reset Database

If you need to start fresh:

```bash
# Stop and remove container
docker stop cybershield-postgres
docker rm cybershield-postgres

# Remove volume
docker volume rm postgres_data

# Run setup script again
.\scripts\setup-postgresql.ps1
```

## Performance Optimization

### 1. Connection Pooling

The application is configured with connection pooling:
- **Pool Size**: 10 connections
- **Max Overflow**: 20 connections
- **Pool Timeout**: 30 seconds
- **Pool Recycle**: 300 seconds

### 2. PostgreSQL Tuning

For production environments, consider these PostgreSQL settings:

```sql
-- Increase shared buffers
ALTER SYSTEM SET shared_buffers = '256MB';

-- Optimize work memory
ALTER SYSTEM SET work_mem = '4MB';

-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
```

## Security Considerations

### 1. Change Default Passwords

```sql
-- Change default password
ALTER USER cybershield_user PASSWORD 'your-secure-password';
```

### 2. Network Security

```bash
# Restrict PostgreSQL to localhost only
docker run -d \
  --name cybershield-postgres \
  -e POSTGRES_DB=cybershield \
  -e POSTGRES_USER=cybershield_user \
  -e POSTGRES_PASSWORD=cybershield_password \
  -p 127.0.0.1:5432:5432 \
  postgres:15-alpine
```

### 3. SSL Configuration

For production, enable SSL:

```sql
-- Enable SSL
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem';
ALTER SYSTEM SET ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key';
```

## Next Steps

After setting up PostgreSQL:

1. **Start the Backend**: Run your FastAPI application
2. **Test SAST Endpoints**: Try creating a new SAST project
3. **Monitor Logs**: Check for any remaining database errors
4. **Run Migrations**: Use Alembic for database schema updates

## Support

If you encounter issues:

1. Check the container logs: `docker logs cybershield-postgres`
2. Verify network connectivity: `docker network ls`
3. Test database connection manually
4. Check the application logs for detailed error messages

## Additional Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [SQLAlchemy Async Documentation](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
- [Docker PostgreSQL Image](https://hub.docker.com/_/postgres)
- [CyberShield Documentation](./README.md)
