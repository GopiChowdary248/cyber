# RASP Agent Deployment Guide

This guide provides step-by-step instructions for deploying RASP agents on different platforms and programming languages.

## Table of Contents
1. [Python Agent Deployment](#python-agent-deployment)
2. [Java Agent Deployment](#java-agent-deployment)
3. [Node.js Agent Deployment](#nodejs-agent-deployment)
4. [Windows Platform Setup](#windows-platform-setup)
5. [Linux Platform Setup](#linux-platform-setup)
6. [Docker Container Setup](#docker-container-setup)
7. [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)

## Python Agent Deployment

### Prerequisites
- Python 3.7+
- pip package manager
- Access to your RASP API endpoint

### Installation

1. **Install RASP Python Agent**
```bash
pip install rasp-agent-python
```

2. **Create Agent Configuration**
```python
# rasp_config.py
import os

RASP_CONFIG = {
    "agent_type": "python",
    "app_name": "your-python-app",
    "language": "python",
    "version": "1.0.0",
    "api_endpoint": "http://localhost:8000/api/rasp",
    "config": {
        "monitoring_level": "high",
        "auto_block": True,
        "log_level": "INFO",
        "heartbeat_interval": 30,
        "hooks": [
            "sqlalchemy.engine.Engine.execute",
            "os.system",
            "subprocess.run",
            "eval",
            "exec",
            "pickle.loads"
        ]
    }
}
```

3. **Initialize Agent in Your Application**
```python
# app.py
from rasp_agent import RASPAgent
from rasp_config import RASP_CONFIG

# Initialize RASP agent
rasp_agent = RASPAgent(RASP_CONFIG)

# Start monitoring
rasp_agent.start()

# Your application code here
def vulnerable_function(user_input):
    # This will be monitored by RASP
    import os
    os.system(user_input)  # This will trigger an alert

if __name__ == "__main__":
    # Your Flask/FastAPI/Django app
    app.run()
```

### Flask Integration Example
```python
from flask import Flask, request
from rasp_agent import RASPAgent

app = Flask(__name__)
rasp_agent = RASPAgent(RASP_CONFIG)

@app.before_request
def before_request():
    # Monitor incoming requests
    rasp_agent.monitor_request(request)

@app.route('/api/users')
def get_users():
    user_id = request.args.get('id')
    # This will be monitored for SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return {"users": []}

if __name__ == "__main__":
    app.run()
```

## Java Agent Deployment

### Prerequisites
- Java 8+
- Maven or Gradle
- Access to your RASP API endpoint

### Installation

1. **Add RASP Agent Dependency**
```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.cybershield</groupId>
    <artifactId>rasp-agent-java</artifactId>
    <version>1.0.0</version>
</dependency>
```

2. **Create Agent Configuration**
```java
// RASPConfig.java
public class RASPConfig {
    public static final String AGENT_TYPE = "java";
    public static final String APP_NAME = "your-java-app";
    public static final String LANGUAGE = "java";
    public static final String VERSION = "1.0.0";
    public static final String API_ENDPOINT = "http://localhost:8000/api/rasp";
    
    public static final Map<String, Object> CONFIG = Map.of(
        "monitoring_level", "high",
        "auto_block", true,
        "log_level", "INFO",
        "heartbeat_interval", 30,
        "hooks", Arrays.asList(
            "java.sql.Statement.executeQuery",
            "java.sql.Statement.executeUpdate",
            "java.lang.Runtime.exec",
            "java.io.FileInputStream.<init>"
        )
    );
}
```

3. **Initialize Agent**
```java
// Application.java
import com.cybershield.rasp.RASPAgent;

public class Application {
    public static void main(String[] args) {
        // Initialize RASP agent
        RASPAgent agent = new RASPAgent(RASPConfig.CONFIG);
        agent.start();
        
        // Your Spring Boot application
        SpringApplication.run(Application.class, args);
    }
}
```

### Spring Boot Integration Example
```java
@RestController
public class UserController {
    
    @Autowired
    private RASPAgent raspAgent;
    
    @GetMapping("/api/users")
    public List<User> getUsers(@RequestParam String id) {
        // This will be monitored for SQL injection
        String query = "SELECT * FROM users WHERE id = " + id;
        return userService.findUsers(query);
    }
}
```

## Node.js Agent Deployment

### Prerequisites
- Node.js 14+
- npm or yarn
- Access to your RASP API endpoint

### Installation

1. **Install RASP Node.js Agent**
```bash
npm install @cybershield/rasp-agent-nodejs
```

2. **Create Agent Configuration**
```javascript
// rasp-config.js
const RASP_CONFIG = {
    agent_type: "nodejs",
    app_name: "your-nodejs-app",
    language: "nodejs",
    version: "1.0.0",
    api_endpoint: "http://localhost:8000/api/rasp",
    config: {
        monitoring_level: "high",
        auto_block: true,
        log_level: "info",
        heartbeat_interval: 30,
        hooks: [
            "child_process.exec",
            "child_process.spawn",
            "fs.readFile",
            "eval"
        ]
    }
};

module.exports = RASP_CONFIG;
```

3. **Initialize Agent**
```javascript
// app.js
const RASPAgent = require('@cybershield/rasp-agent-nodejs');
const RASP_CONFIG = require('./rasp-config');

// Initialize RASP agent
const raspAgent = new RASPAgent(RASP_CONFIG);

// Start monitoring
raspAgent.start();

// Your Express.js application
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    const userId = req.query.id;
    // This will be monitored for SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    res.json({ users: [] });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

### Express.js Middleware Example
```javascript
const express = require('express');
const RASPAgent = require('@cybershield/rasp-agent-nodejs');

const app = express();
const raspAgent = new RASPAgent(RASP_CONFIG);

// RASP middleware
app.use((req, res, next) => {
    raspAgent.monitorRequest(req, res);
    next();
});

app.get('/api/users', (req, res) => {
    // Your endpoint logic
    res.json({ users: [] });
});
```

## Windows Platform Setup

### System Requirements
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- .NET Framework 4.7.2+ (for Java applications)

### Installation Steps

1. **Download and Install Prerequisites**
```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Python, Java, Node.js
choco install python nodejs openjdk -y
```

2. **Deploy RASP Backend**
```powershell
# Run the deployment script
.\deploy-rasp-production.ps1 -Environment production -DatabasePassword "your_password"
```

3. **Configure Windows Firewall**
```powershell
# Allow RASP API port
New-NetFirewallRule -DisplayName "RASP API" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow

# Allow agent communication
New-NetFirewallRule -DisplayName "RASP Agent Communication" -Direction Outbound -Protocol TCP -RemotePort 8000 -Action Allow
```

4. **Create Windows Service (Optional)**
```powershell
# Create service for RASP backend
New-Service -Name "RASPBackend" -BinaryPathName "python.exe C:\path\to\backend\main.py" -StartupType Automatic
Start-Service -Name "RASPBackend"
```

## Linux Platform Setup

### System Requirements
- Ubuntu 18.04+ or CentOS 7+
- Python 3.7+
- Java 8+
- Node.js 14+

### Installation Steps

1. **Install Dependencies**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip openjdk-11-jdk nodejs npm postgresql postgresql-contrib redis-server

# CentOS/RHEL
sudo yum update -y
sudo yum install -y python3 python3-pip java-11-openjdk nodejs npm postgresql postgresql-server redis
```

2. **Deploy RASP Backend**
```bash
# Make script executable
chmod +x deploy-rasp-backend.sh

# Run deployment
./deploy-rasp-backend.sh --environment production --db-password "your_password"
```

3. **Configure Systemd Services**
```bash
# Create RASP backend service
sudo tee /etc/systemd/system/rasp-backend.service << EOF
[Unit]
Description=RASP Backend Service
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=rasp
WorkingDirectory=/opt/rasp/backend
ExecStart=/usr/bin/python3 main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable rasp-backend
sudo systemctl start rasp-backend
```

4. **Configure Firewall**
```bash
# Allow RASP API port
sudo ufw allow 8000/tcp

# Allow agent communication
sudo ufw allow out 8000/tcp
```

## Docker Container Setup

### Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  rasp-backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/cybershield_rasp
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - ./logs:/app/logs

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=cybershield_rasp
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-rasp-db.sql:/docker-entrypoint-initdb.d/init.sql

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"

  # Example Python application with RASP agent
  python-app:
    build: ./python-app
    environment:
      - RASP_API_ENDPOINT=http://rasp-backend:8000/api/rasp
    depends_on:
      - rasp-backend

volumes:
  postgres_data:
```

### Dockerfile for Python Application
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install RASP agent
RUN pip install rasp-agent-python

# Copy application code
COPY . .

# Copy RASP configuration
COPY rasp-config.py .

# Run application with RASP agent
CMD ["python", "app.py"]
```

## Monitoring and Troubleshooting

### Health Checks

1. **API Health Check**
```bash
curl -X GET http://localhost:8000/api/rasp/agents
```

2. **Dashboard Access**
```bash
# Open in browser
http://localhost:8000/docs
```

3. **Agent Status Check**
```bash
curl -X GET http://localhost:8000/api/rasp/dashboard/agent-status
```

### Log Monitoring

1. **Backend Logs**
```bash
# View backend logs
tail -f logs/rasp-backend.log

# View systemd logs (Linux)
sudo journalctl -u rasp-backend -f
```

2. **Agent Logs**
```python
# Python agent logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('rasp-agent')
```

### Common Issues and Solutions

1. **Agent Not Connecting**
- Check API endpoint URL
- Verify network connectivity
- Check firewall settings
- Review agent configuration

2. **False Positives**
- Adjust detection rules sensitivity
- Whitelist legitimate patterns
- Review application behavior

3. **Performance Issues**
- Reduce monitoring level
- Increase heartbeat interval
- Optimize detection patterns

### Performance Tuning

1. **Optimize Detection Rules**
```json
{
    "vuln_type": "SQLi",
    "pattern": ".*SELECT.*FROM.*\\+.*",
    "severity": "critical",
    "auto_block": true,
    "performance_impact": "low"
}
```

2. **Configure Monitoring Levels**
- `low`: Basic monitoring
- `medium`: Standard monitoring
- `high`: Comprehensive monitoring

3. **Heartbeat Configuration**
```json
{
    "heartbeat_interval": 30,
    "batch_size": 100,
    "timeout": 5000
}
```

## Security Best Practices

1. **Network Security**
- Use HTTPS for API communication
- Implement API authentication
- Restrict network access

2. **Agent Security**
- Validate agent configurations
- Use secure communication channels
- Implement agent authentication

3. **Monitoring Security**
- Encrypt sensitive data
- Implement audit logging
- Regular security assessments

## Support and Documentation

- **API Documentation**: http://localhost:8000/docs
- **Agent Documentation**: See language-specific guides
- **Troubleshooting**: Check logs and health endpoints
- **Community Support**: GitHub issues and discussions

For additional support, refer to the main RASP documentation and deployment guides. 