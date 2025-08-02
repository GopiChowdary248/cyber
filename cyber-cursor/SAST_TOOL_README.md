# SAST Tool - Comprehensive Static Application Security Testing

## Overview

The SAST Tool is a comprehensive Static Application Security Testing solution similar to SonarQube, designed to scan source code for vulnerabilities, bugs, and code smells. It provides AI-driven recommendations, multi-language support, and seamless DevSecOps integration.

## 🚀 Features

### Core Functionality
- **Multi-Language Support**: Python, JavaScript, TypeScript, Java, Go, Ruby
- **Multiple Scanning Tools**: Bandit, PyLint, ESLint, Semgrep, Gosec, Brakeman
- **AI-Powered Recommendations**: Automated code fix suggestions using OpenAI
- **Risk Scoring**: Intelligent vulnerability prioritization
- **Real-Time Scanning**: Background task processing for large projects
- **Comprehensive Reporting**: PDF, CSV, and JSON report formats

### DevSecOps Integration
- **GitHub Integration**: Webhook support and check runs
- **GitLab Integration**: Pipeline integration and merge request comments
- **Jenkins Integration**: Pipeline job creation and status reporting
- **CI/CD Pipeline**: Automated scanning in build processes

### Advanced Features
- **Real-Time Code Review**: VS Code/IntelliJ plugin support
- **Cloud Misconfiguration Scan**: AWS, Azure, GCP security checks
- **Bug Tracking Integration**: Automatic Jira/GitHub issue creation
- **Compliance Reporting**: SOC2, PCI-DSS, HIPAA compliance reports

## 🏗️ Architecture

### Tech Stack
- **Backend**: Python FastAPI
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Frontend**: React Native (responsive dashboard)
- **Scanning Engine**: Custom Python with multiple security tools
- **AI Engine**: OpenAI GPT-4 integration
- **Background Tasks**: Celery with Redis
- **Containerization**: Docker & Docker Compose
- **Monitoring**: Prometheus & Grafana

### Architecture Flow
```
Developer → Upload Code → FastAPI Backend → Scanning Engine → PostgreSQL → React Native UI
                                    ↓
                            AI Recommendation Engine
                                    ↓
                            DevSecOps Integration
```

## 📦 Installation

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Node.js 18+
- PostgreSQL 13+

### Quick Start

1. **Clone the repository**
```bash
git clone <repository-url>
cd cyber-cursor
```

2. **Set up environment variables**
```bash
cp env.example .env
# Edit .env with your configuration
```

3. **Start the SAST tool**
```bash
# Using Docker Compose
docker-compose -f docker-compose.sast.yml up -d

# Or run individually
cd backend
python main_sast.py
```

4. **Access the application**
- **API Documentation**: http://localhost:8000/docs
- **Frontend Dashboard**: http://localhost:3000
- **Health Check**: http://localhost:8000/health

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sast_db

# AI Integration
OPENAI_API_KEY=your_openai_api_key

# DevSecOps Integration
GITHUB_WEBHOOK_SECRET=your_github_secret
GITLAB_WEBHOOK_SECRET=your_gitlab_secret
JENKINS_URL=http://jenkins:8080

# Security
JWT_SECRET_KEY=your_jwt_secret
ENCRYPTION_KEY=your_encryption_key
```

### Scanning Configuration
```yaml
# config/scanning.yaml
tools:
  python:
    - bandit
    - pylint
    - semgrep
  javascript:
    - eslint
    - semgrep
  java:
    - spotbugs
    - pmd
  go:
    - gosec
  ruby:
    - brakeman

severity_levels:
  critical: 10
  high: 7
  medium: 4
  low: 1
  info: 0
```

## 📚 Usage

### API Endpoints

#### Start a Scan
```bash
curl -X POST "http://localhost:8000/api/v1/sast/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "project_path": "/path/to/project",
    "scan_type": "full",
    "languages": ["python", "javascript"],
    "tools": ["bandit", "pylint", "eslint"]
  }'
```

#### Upload and Scan Files
```bash
curl -X POST "http://localhost:8000/api/v1/sast/scan/upload" \
  -F "file=@/path/to/code.zip" \
  -F "scan_type=full" \
  -F "languages=python,javascript"
```

#### Get Scan Results
```bash
curl "http://localhost:8000/api/v1/sast/scans/{scan_id}/vulnerabilities"
```

#### Get AI Recommendations
```bash
curl "http://localhost:8000/api/v1/sast/vulnerabilities/{vuln_id}/recommendations"
```

### CI/CD Integration

#### GitHub Actions
```yaml
name: SAST Scan
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SAST Scan
        run: |
          curl -X POST "http://sast-tool:8000/api/v1/sast/scan" \
            -H "Content-Type: application/json" \
            -d '{"project_path": ".", "scan_type": "full"}'
```

#### GitLab CI
```yaml
sast:
  stage: test
  script:
    - curl -X POST "http://sast-tool:8000/api/v1/sast/scan" \
        -H "Content-Type: application/json" \
        -d '{"project_path": ".", "scan_type": "full"}'
```

## 🧪 Testing

### Run Comprehensive Tests
```bash
# Python
cd test-app
python sast-tool-test.py

# PowerShell
cd test-app
.\sast-tool-test.ps1
```

### Test Individual Components
```bash
# Test scanning engine
python -m pytest tests/test_scanner.py

# Test AI recommendations
python -m pytest tests/test_ai_recommendations.py

# Test API endpoints
python -m pytest tests/test_api.py
```

## 📊 Monitoring

### Health Checks
```bash
# Check service health
curl http://localhost:8000/health

# Check database connection
curl http://localhost:8000/api/v1/sast/health/db

# Check scanning tools
curl http://localhost:8000/api/v1/sast/health/tools
```

### Metrics
- **Scan Duration**: Average time per scan
- **Vulnerability Detection Rate**: Success rate of vulnerability detection
- **False Positive Rate**: Accuracy of vulnerability detection
- **Tool Performance**: Individual tool success rates

## 🔒 Security Considerations

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (Admin, Developer, Viewer)
- API key authentication for CI/CD integration

### Data Protection
- Encrypted storage of sensitive data
- Secure file upload validation
- Audit logging for all operations

### Network Security
- HTTPS/TLS encryption
- CORS configuration
- Rate limiting and DDoS protection

## 🚀 Deployment

### Docker Deployment
```bash
# Build and run
docker-compose -f docker-compose.sast.yml up -d

# Scale services
docker-compose -f docker-compose.sast.yml up -d --scale sast_worker=3
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n sast-tool
```

### Production Considerations
- Use external PostgreSQL database
- Configure Redis for caching
- Set up monitoring with Prometheus/Grafana
- Enable SSL/TLS termination
- Configure backup strategies

## 🔧 Troubleshooting

### Common Issues

#### Scan Fails to Start
```bash
# Check service logs
docker-compose -f docker-compose.sast.yml logs sast_backend

# Verify database connection
curl http://localhost:8000/api/v1/sast/health/db
```

#### No Vulnerabilities Detected
```bash
# Check scanning tools installation
curl http://localhost:8000/api/v1/sast/health/tools

# Verify project path and file permissions
ls -la /path/to/project
```

#### AI Recommendations Not Working
```bash
# Check OpenAI API key
echo $OPENAI_API_KEY

# Test OpenAI connection
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models
```

### Log Analysis
```bash
# View application logs
docker-compose -f docker-compose.sast.yml logs -f sast_backend

# Check scanning worker logs
docker-compose -f docker-compose.sast.yml logs -f sast_worker
```

## 📈 Performance Optimization

### Scanning Performance
- **Parallel Processing**: Run multiple tools concurrently
- **Incremental Scans**: Only scan changed files
- **Caching**: Cache scan results for unchanged files
- **Resource Limits**: Configure memory and CPU limits

### Database Optimization
- **Indexing**: Optimize database indexes for queries
- **Connection Pooling**: Configure connection pool settings
- **Partitioning**: Partition large tables by date

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd cyber-cursor

# Set up development environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r backend/requirements-sast.txt

# Run development server
cd backend
python main_sast.py --reload
```

### Code Style
- Follow PEP 8 for Python code
- Use Black for code formatting
- Run linting with flake8 and mypy
- Write comprehensive tests

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test category
pytest tests/test_scanner.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- [API Documentation](http://localhost:8000/docs)
- [User Guide](docs/user-guide.md)
- [Developer Guide](docs/developer-guide.md)

### Community
- [GitHub Issues](https://github.com/your-repo/issues)
- [Discussions](https://github.com/your-repo/discussions)
- [Wiki](https://github.com/your-repo/wiki)

### Professional Support
- Email: support@cybershield.com
- Phone: +1-555-123-4567
- Enterprise: enterprise@cybershield.com

---

**Built with ❤️ by the CyberShield Team** 