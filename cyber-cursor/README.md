# Cyber Cursor DAST

A comprehensive Dynamic Application Security Testing (DAST) platform built with FastAPI and React, featuring Burp Suite-like functionality for web application security testing.

## Features

### Phase 1 (High Priority) - ✅ Completed
- **HTTP History Tab**: Complete traffic analysis with filtering and search
- **Repeater Tool**: Manual request manipulation and testing
- **Tabbed Interface**: Unified navigation across all tools
- **Context Menus**: Right-click actions for enhanced workflow

### Phase 2 (Medium Priority) - ✅ Completed
- **Intruder Tool**: Automated testing with multiple attack types
- **Scanner Integration**: Active and passive scanning capabilities
- **Virtual Scrolling**: Performance optimization for large datasets
- **WebSocket Updates**: Real-time traffic and status updates

### Phase 3 (Low Priority) - 🔄 Foundation Ready
- **Macro System**: Automation and workflow orchestration
- **Session Management**: State persistence and configuration
- **Collaboration Features**: Team workflow and sharing
- **Mobile Optimization**: Touch interface and responsive design

## Architecture

```
cyber-cursor/
├── frontend/                 # React frontend application
│   ├── src/
│   │   ├── components/DAST/ # DAST-specific components
│   │   │   ├── Scanner/     # Vulnerability scanner
│   │   │   ├── Crawler/     # Web crawler
│   │   │   ├── Rules/       # Match/replace rules
│   │   │   ├── Proxy/       # HTTP proxy engine
│   │   │   ├── Intruder/    # Automated testing tool
│   │   │   └── Repeater/    # Manual request tool
│   │   └── services/        # API service layer
├── backend/                  # FastAPI backend application
│   ├── app/
│   │   ├── api/v1/          # API endpoints
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── services/        # Business logic layer
│   │   └── core/            # Core functionality
│   └── main.py              # FastAPI application entry point
└── docker-compose.yml       # PostgreSQL database setup
```

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.8+
- Node.js 16+
- PostgreSQL 15+

### 1. Start Database
```bash
# Start PostgreSQL database
docker-compose up -d postgres

# Wait for database to be ready (check with docker-compose ps)
```

### 2. Backend Setup
```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://postgres:password@localhost:5432/cyber_cursor_dast"
export SECRET_KEY="your-secret-key-change-in-production"

# Run the backend
python main.py
```

The backend will be available at `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

### 3. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

The frontend will be available at `http://localhost:3000`

## Database Schema

The system uses PostgreSQL with the following main tables:

- **dast_projects**: Main project container
- **dast_scans**: Security scan instances
- **dast_scan_issues**: Vulnerability findings
- **dast_http_entries**: HTTP traffic history
- **dast_crawl_results**: Web crawler results
- **dast_match_replace_rules**: Traffic modification rules
- **dast_intruder_attacks**: Automated testing attacks
- **dast_repeater_requests**: Manual request history

## API Endpoints

### Core DAST Endpoints
- `GET /api/v1/dast/projects/{project_id}/status` - Project status
- `GET /api/v1/dast/projects/{project_id}/http-history` - HTTP traffic history
- `POST /api/v1/dast/projects/{project_id}/scanner/scans` - Create security scan
- `POST /api/v1/dast/projects/{project_id}/crawler/start` - Start web crawler
- `GET /api/v1/dast/projects/{project_id}/rules` - Get match/replace rules

### Tool-Specific Endpoints
- **Scanner**: `/api/v1/dast/projects/{project_id}/scanner/*`
- **Crawler**: `/api/v1/dast/projects/{project_id}/crawler/*`
- **Intruder**: `/api/v1/dast/projects/{project_id}/intruder/*`
- **Repeater**: `/api/v1/dast/projects/{project_id}/repeater/*`
- **Proxy**: `/api/v1/dast/projects/{project_id}/proxy/*`

### WebSocket Endpoints
- `WS /api/v1/dast/projects/{project_id}/ws` - Real-time updates

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/cyber_cursor_dast

# Security
SECRET_KEY=your-secret-key-change-in-production

# Debug
SQL_DEBUG=false
```

### Database Configuration
The system automatically creates all necessary tables on startup. You can also use Alembic for migrations:

```bash
# Initialize Alembic
alembic init alembic

# Create migration
alembic revision --autogenerate -m "Initial migration"

# Apply migration
alembic upgrade head
```

## Development

### Backend Development
```bash
cd backend

# Install development dependencies
pip install -r requirements.txt

# Run with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Run tests
pytest
```

### Frontend Development
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Run tests
npm test

# Build for production
npm run build
```

### Database Development
```bash
# Access PostgreSQL
docker exec -it cyber_cursor_postgres psql -U postgres -d cyber_cursor_dast

# Access PgAdmin
# Open http://localhost:5050
# Login: admin@cybercursor.com / admin
```

## Testing

### API Testing
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test with authentication (mock token)
curl -H "Authorization: Bearer mock_token" http://localhost:8000/api/v1/dast/projects/test/status
```

### WebSocket Testing
```bash
# Test WebSocket connection
wscat -c "ws://localhost:8000/api/v1/dast/projects/test/ws?token=mock_token"
```

## Security Features

- **Authentication**: JWT-based authentication system
- **Authorization**: Role-based access control
- **Input Validation**: Pydantic schema validation
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **CORS Configuration**: Configurable cross-origin resource sharing
- **Rate Limiting**: Built-in request throttling (configurable)

## Performance Features

- **Virtual Scrolling**: Efficient handling of large datasets
- **Database Indexing**: Optimized PostgreSQL queries
- **Connection Pooling**: SQLAlchemy connection management
- **Async Operations**: Non-blocking I/O operations
- **WebSocket Management**: Efficient real-time communication

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the API documentation at `/docs`
- Review the code examples in the frontend components

## Roadmap

### Upcoming Features
- **Advanced Scanning**: Machine learning-based vulnerability detection
- **Integration APIs**: CI/CD pipeline integration
- **Reporting Engine**: Advanced report generation
- **Team Collaboration**: Multi-user project management
- **Cloud Deployment**: Kubernetes and cloud-native deployment

### Performance Improvements
- **Caching Layer**: Redis-based caching system
- **Background Tasks**: Celery-based task queue
- **Database Optimization**: Advanced query optimization
- **Load Balancing**: Horizontal scaling support 