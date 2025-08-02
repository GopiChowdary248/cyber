# 🛡️ CyberShield End-to-End Testing Suite

This directory contains comprehensive end-to-end testing tools for the CyberShield cybersecurity platform.

## 📋 Test Scripts Overview

### 1. **Basic Test** (`basic-test.py`)
- **Purpose**: Quick infrastructure and connectivity testing
- **Duration**: ~30 seconds
- **Authentication**: Not required
- **Best for**: Initial setup verification

### 2. **Quick Test** (`quick-test.py`)
- **Purpose**: Core functionality testing with authentication
- **Duration**: ~1 minute
- **Authentication**: Required (demo accounts)
- **Best for**: Regular testing during development

### 3. **Comprehensive Test** (`comprehensive-e2e-test.py`)
- **Purpose**: Full end-to-end validation
- **Duration**: ~5-10 minutes
- **Authentication**: Required (demo accounts)
- **Best for**: Pre-deployment validation

### 4. **PowerShell Runner** (`run-comprehensive-e2e-test.ps1`)
- **Purpose**: Windows-friendly test execution
- **Features**: Application startup, dependency management
- **Best for**: Windows users and CI/CD pipelines

## 🚀 Quick Start

### Prerequisites
1. **Docker Desktop** - Running
2. **Python 3.7+** - Installed
3. **CyberShield Application** - Running (`docker-compose up -d`)

### Running Tests

#### Option 1: Basic Infrastructure Test
```bash
cd test-app
python basic-test.py
```

#### Option 2: Quick Functional Test
```bash
cd test-app
python quick-test.py
```

#### Option 3: Comprehensive Test
```bash
cd test-app
python comprehensive-e2e-test.py
```

#### Option 4: PowerShell (Windows)
```powershell
cd test-app
.\run-comprehensive-e2e-test.ps1 -StartApplication
```

## 📊 Test Results

### Current Test Results (Latest Run)
```
✅ Infrastructure: 4/6 tests passed
✅ Backend Health: 3/3 tests passed
✅ Frontend: 3/3 tests passed
✅ Database: 1/1 tests passed
❌ Security Endpoints: 0/3 tests passed (404 errors)
✅ Performance: 1/1 tests passed

Overall Success Rate: 70.6%
```

### Test Categories

#### 1. **Infrastructure Testing**
- Docker container status
- Port accessibility (3000, 8000, 5432, 6379)
- Service connectivity

#### 2. **Backend API Testing**
- Health endpoint validation
- API documentation accessibility
- OpenAPI schema validation

#### 3. **Frontend Testing**
- Main page accessibility
- Login page functionality
- Dashboard page routing

#### 4. **Database Testing**
- Connection validation
- User data verification
- Query performance

#### 5. **Security Module Testing**
- SAST endpoint validation
- DAST endpoint validation
- Security summary aggregation

#### 6. **Performance Testing**
- API response times
- Frontend load times
- Database query performance

## 🔧 Test Configuration

### Environment Variables
```bash
# Application URLs
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:8000

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=cybershield_user
DB_PASSWORD=cybershield_password
DB_NAME=cybershield

# Test Configuration
TEST_TIMEOUT=10
MAX_RETRIES=3
```

### Demo Accounts
The application includes pre-configured demo accounts for testing:

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@cybershield.com | password |
| Analyst | analyst@cybershield.com | password |
| User | user@cybershield.com | password |
| Demo | demo@cybershield.com | password |

## 📈 Performance Benchmarks

### Response Time Targets
- **API Endpoints**: < 1 second (PASS), < 3 seconds (WARN), > 3 seconds (FAIL)
- **Frontend Pages**: < 2 seconds (PASS), < 5 seconds (WARN), > 5 seconds (FAIL)
- **Database Queries**: < 500ms (PASS), < 1 second (WARN), > 1 second (FAIL)

### Resource Usage Limits
- **CPU**: < 80% per container
- **Memory**: < 2GB per container
- **Disk I/O**: < 100MB/s

## 🐛 Troubleshooting

### Common Issues

#### 1. **Application Not Starting**
```bash
# Check Docker status
docker-compose ps

# Restart containers
docker-compose down
docker-compose up -d

# Check logs
docker-compose logs
```

#### 2. **Authentication Failures**
```bash
# Verify demo accounts exist
python check-db.py

# Reset database if needed
docker-compose down
docker volume rm cyber-cursor_postgres_data
docker-compose up -d
```

#### 3. **Port Conflicts**
```bash
# Check port usage
netstat -an | findstr :3000
netstat -an | findstr :8000

# Kill conflicting processes (Windows)
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

#### 4. **Test Script Errors**
```bash
# Install dependencies
pip install requests docker asyncpg

# Check Python version
python --version

# Run with verbose output
python basic-test.py --verbose
```

### Debug Mode

Enable detailed logging for troubleshooting:
```bash
# Python test with debug
python comprehensive-e2e-test.py --debug

# PowerShell with verbose
.\run-comprehensive-e2e-test.ps1 -Verbose
```

## 📄 Test Reports

### Report Types
1. **Console Output**: Real-time test results
2. **JSON Reports**: Detailed structured data
3. **Log Files**: Comprehensive execution logs

### Report Location
```
test-app/
├── comprehensive_e2e_test_report_YYYYMMDD_HHMMSS.json
├── quick_test_report_YYYYMMDD_HHMMSS.json
├── basic_test_report_YYYYMMDD_HHMMSS.json
└── logs/
    └── test_execution.log
```

### Report Structure
```json
{
  "test_summary": {
    "test_date": "2024-01-15T10:30:00Z",
    "total_tests": 25,
    "passed_tests": 23,
    "failed_tests": 2,
    "success_rate": 92.0,
    "overall_status": "PASS"
  },
  "detailed_results": {
    "infrastructure": [...],
    "backend": [...],
    "frontend": [...],
    "database": [...],
    "security_modules": [...],
    "performance": [...]
  },
  "recommendations": [...]
}
```

## 🔄 Continuous Integration

### GitHub Actions Example
```yaml
name: E2E Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Start Application
        run: docker-compose up -d
      - name: Wait for Services
        run: sleep 60
      - name: Run Basic Tests
        run: |
          cd test-app
          python basic-test.py
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: test-app/*.json
```

### Local CI/CD Pipeline
```bash
#!/bin/bash
# test-pipeline.sh

echo "🚀 Starting E2E Test Pipeline"

# Start application
docker-compose up -d

# Wait for services
echo "⏳ Waiting for services..."
sleep 60

# Run tests
echo "🧪 Running tests..."
cd test-app
python basic-test.py

# Check results
if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ Tests failed!"
    exit 1
fi
```

## 📚 Additional Resources

### Documentation
- [Comprehensive Testing Guide](COMPREHENSIVE_E2E_TESTING_GUIDE.md)
- [API Documentation](http://localhost:8000/docs)
- [Application Security Guide](../docs/ApplicationSecurity.md)

### Tools
- [Database Checker](check-db.py)
- [Login Tester](test-login.py)
- [Attack Simulator](attack-simulator.py)

### Support
- [GitHub Issues](https://github.com/your-repo/issues)
- [Documentation Wiki](../docs/)
- [Community Forum](https://community.cybershield.com)

## 🎯 Best Practices

### Test Execution
1. **Run tests in isolation** - Ensure clean environment
2. **Use consistent data** - Same test data across runs
3. **Monitor resources** - Check system resources during tests
4. **Document failures** - Keep detailed logs of failures
5. **Regular testing** - Run tests after each deployment

### Test Maintenance
1. **Update test data** - Keep test data current
2. **Review performance** - Monitor test execution times
3. **Validate assumptions** - Verify test assumptions remain valid
4. **Version control** - Track test script changes
5. **Documentation** - Keep testing documentation updated

---

**Last Updated:** January 15, 2024  
**Version:** 1.0.0  
**Maintainer:** CyberShield Development Team 