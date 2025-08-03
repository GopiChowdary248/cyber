# RASP Agent Configuration Guide

## Overview

This guide provides comprehensive instructions for configuring RASP (Runtime Application Self-Protection) agents for your target applications on Windows and Linux platforms. The RASP agents provide real-time monitoring and protection by instrumenting application runtime to detect and block attacks.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Agent Architecture](#agent-architecture)
3. [Windows Agent Configuration](#windows-agent-configuration)
4. [Linux Agent Configuration](#linux-agent-configuration)
5. [Language-Specific Configuration](#language-specific-configuration)
6. [Detection Rules Setup](#detection-rules-setup)
7. [SIEM/SOAR Integration](#siemsoar-integration)
8. [Monitoring and Tuning](#monitoring-and-tuning)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Windows**: Windows 10/11, Windows Server 2016+
- **Linux**: Ubuntu 18.04+, CentOS 7+, RHEL 7+
- **Python**: 3.8+ (for Python applications)
- **Java**: JDK 8+ (for Java applications)
- **Node.js**: 14+ (for Node.js applications)
- **.NET**: .NET Core 3.1+ or .NET Framework 4.7+ (for .NET applications)

### Network Requirements

- Access to RASP backend API (default: http://localhost:8000)
- PostgreSQL database connectivity
- Redis connectivity (optional, for caching)
- Outbound HTTPS for agent updates and telemetry

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RASP Agent Architecture                   │
├─────────────────────────────────────────────────────────────┤
│  Application Layer                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Web App       │  │   API Service   │  │  Background  │ │
│  │   (Python/Java/ │  │   (REST/GraphQL)│  │   Process    │ │
│  │    Node.js/.NET)│  │                 │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  RASP Agent Layer                                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  Runtime Hooks  │  │  Detection      │  │  Telemetry   │ │
│  │  (Method/Function│  │  Engine         │  │  & Logging   │ │
│  │   Interception) │  │  (Rules Engine) │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  Communication Layer                                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  API Client     │  │  Message Queue  │  │  WebSocket   │ │
│  │  (HTTP/HTTPS)   │  │  (Redis/Kafka)  │  │  (Real-time) │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Windows Agent Configuration

### 1. Python Applications

#### Installation

```powershell
# Install RASP agent for Python
pip install cybershield-rasp-agent

# Or install from source
git clone https://github.com/your-org/cybershield-rasp-agent
cd cybershield-rasp-agent
pip install -e .
```

#### Configuration File (`rasp_config.yaml`)

```yaml
# RASP Agent Configuration for Python Applications
agent:
  name: "web-app-prod-01"
  language: "python"
  version: "1.0.0"
  environment: "production"

backend:
  api_url: "http://localhost:8000"
  api_key: "your-api-key-here"
  heartbeat_interval: 30  # seconds
  timeout: 10  # seconds

monitoring:
  # Database monitoring
  database:
    enabled: true
    hooks:
      - "sqlite3.connect"
      - "psycopg2.connect"
      - "mysql.connector.connect"
      - "pymongo.MongoClient"
  
  # File system monitoring
  filesystem:
    enabled: true
    hooks:
      - "open"
      - "os.path.join"
      - "pathlib.Path"
  
  # Command execution monitoring
  command:
    enabled: true
    hooks:
      - "os.system"
      - "subprocess.run"
      - "subprocess.Popen"
  
  # Network monitoring
  network:
    enabled: true
    hooks:
      - "urllib.request.urlopen"
      - "requests.get"
      - "requests.post"
      - "socket.socket"

detection:
  # SQL Injection detection
  sql_injection:
    enabled: true
    patterns:
      - ".*SELECT.*FROM.*\\+.*"
      - ".*UNION.*SELECT.*"
      - ".*DROP.*TABLE.*"
    severity: "critical"
    auto_block: true
  
  # Command Injection detection
  command_injection:
    enabled: true
    patterns:
      - ".*(;|&&|\\|).*"
      - ".*`.*`.*"
    severity: "critical"
    auto_block: true
  
  # Path Traversal detection
  path_traversal:
    enabled: true
    patterns:
      - ".*\\.\\./.*"
      - ".*\\.\\.\\\\.*"
    severity: "high"
    auto_block: true

logging:
  level: "INFO"
  file: "logs/rasp-agent.log"
  max_size: "10MB"
  backup_count: 5
  format: "json"

telemetry:
  enabled: true
  interval: 60  # seconds
  metrics:
    - "attack_count"
    - "blocked_requests"
    - "response_time"
    - "memory_usage"
```

#### Integration with Flask Application

```python
# app.py
from flask import Flask, request, jsonify
from rasp_agent import RASPAgent

# Initialize RASP agent
rasp_agent = RASPAgent(config_file="rasp_config.yaml")

app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def get_users():
    # RASP agent automatically monitors this endpoint
    user_id = request.args.get('id')
    
    # This will be monitored for SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    return jsonify({"users": []})

@app.route('/api/execute', methods=['POST'])
def execute_command():
    command = request.json.get('command')
    
    # This will be monitored for command injection
    import os
    result = os.system(command)
    
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(debug=True)
```

### 2. Java Applications

#### Maven Dependency

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.cybershield</groupId>
    <artifactId>rasp-agent</artifactId>
    <version>1.0.0</version>
</dependency>
```

#### Java Agent Configuration

```java
// RASPConfig.java
package com.cybershield.rasp;

import com.cybershield.rasp.config.RASPConfig;
import com.cybershield.rasp.agent.RASPAgent;

public class RASPConfig {
    public static void initialize() {
        RASPConfig config = RASPConfig.builder()
            .agentName("java-app-prod-01")
            .language("java")
            .version("1.0.0")
            .environment("production")
            .backendUrl("http://localhost:8000")
            .apiKey("your-api-key-here")
            .heartbeatInterval(30)
            .timeout(10)
            .build();
        
        RASPAgent.initialize(config);
    }
}
```

#### Spring Boot Integration

```java
// Application.java
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.cybershield.rasp.RASPConfig;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        // Initialize RASP agent
        RASPConfig.initialize();
        
        SpringApplication.run(Application.class, args);
    }
}
```

### 3. .NET Applications

#### NuGet Package

```xml
<!-- .csproj -->
<PackageReference Include="CyberShield.RASP" Version="1.0.0" />
```

#### .NET Configuration

```csharp
// Program.cs
using CyberShield.RASP;

var builder = WebApplication.CreateBuilder(args);

// Initialize RASP agent
RASPConfig config = new RASPConfig
{
    AgentName = "dotnet-app-prod-01",
    Language = "dotnet",
    Version = "1.0.0",
    Environment = "production",
    BackendUrl = "http://localhost:8000",
    ApiKey = "your-api-key-here",
    HeartbeatInterval = 30,
    Timeout = 10
};

RASPAgent.Initialize(config);

var app = builder.Build();
```

## Linux Agent Configuration

### 1. System-wide Installation

```bash
# Install RASP agent system-wide
sudo apt-get update
sudo apt-get install cybershield-rasp-agent

# Or install from source
git clone https://github.com/your-org/cybershield-rasp-agent
cd cybershield-rasp-agent
sudo python3 setup.py install
```

### 2. Python Applications on Linux

#### Configuration File (`/etc/cybershield/rasp-config.yaml`)

```yaml
# RASP Agent Configuration for Linux Python Applications
agent:
  name: "linux-web-app-01"
  language: "python"
  version: "1.0.0"
  environment: "production"

backend:
  api_url: "http://localhost:8000"
  api_key: "your-api-key-here"
  heartbeat_interval: 30
  timeout: 10

monitoring:
  # Enhanced Linux-specific monitoring
  database:
    enabled: true
    hooks:
      - "sqlite3.connect"
      - "psycopg2.connect"
      - "mysql.connector.connect"
      - "pymongo.MongoClient"
  
  filesystem:
    enabled: true
    hooks:
      - "open"
      - "os.path.join"
      - "pathlib.Path"
      - "shutil.copy"
      - "shutil.move"
  
  command:
    enabled: true
    hooks:
      - "os.system"
      - "subprocess.run"
      - "subprocess.Popen"
      - "subprocess.call"
  
  network:
    enabled: true
    hooks:
      - "urllib.request.urlopen"
      - "requests.get"
      - "requests.post"
      - "socket.socket"
      - "http.client.HTTPConnection"
  
  # Linux-specific monitoring
  process:
    enabled: true
    hooks:
      - "os.fork"
      - "os.exec"
      - "multiprocessing.Process"
  
  memory:
    enabled: true
    hooks:
      - "mmap.mmap"
      - "ctypes.cast"

detection:
  sql_injection:
    enabled: true
    patterns:
      - ".*SELECT.*FROM.*\\+.*"
      - ".*UNION.*SELECT.*"
      - ".*DROP.*TABLE.*"
      - ".*INSERT.*INTO.*VALUES.*"
    severity: "critical"
    auto_block: true
  
  command_injection:
    enabled: true
    patterns:
      - ".*(;|&&|\\||`).*"
      - ".*\\$\\(.*\\).*"
      - ".*eval\\(.*\\).*"
    severity: "critical"
    auto_block: true
  
  path_traversal:
    enabled: true
    patterns:
      - ".*\\.\\./.*"
      - ".*\\.\\.\\\\.*"
      - ".*/etc/passwd.*"
      - ".*/proc/.*"
    severity: "high"
    auto_block: true
  
  # Linux-specific detections
  privilege_escalation:
    enabled: true
    patterns:
      - ".*sudo.*"
      - ".*su.*"
      - ".*chmod.*777.*"
    severity: "high"
    auto_block: false  # Log only, don't block

logging:
  level: "INFO"
  file: "/var/log/cybershield/rasp-agent.log"
  max_size: "10MB"
  backup_count: 5
  format: "json"
  syslog: true

telemetry:
  enabled: true
  interval: 60
  metrics:
    - "attack_count"
    - "blocked_requests"
    - "response_time"
    - "memory_usage"
    - "cpu_usage"
    - "disk_usage"
```

### 3. Docker Container Integration

#### Dockerfile with RASP Agent

```dockerfile
# Dockerfile
FROM python:3.9-slim

# Install RASP agent
RUN pip install cybershield-rasp-agent

# Copy application code
COPY app.py /app/app.py
COPY rasp_config.yaml /app/rasp_config.yaml

# Set working directory
WORKDIR /app

# Initialize RASP agent
ENV RASP_CONFIG_FILE=/app/rasp_config.yaml

# Run application with RASP agent
CMD ["python", "-m", "rasp_agent", "app.py"]
```

#### Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  web-app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - RASP_CONFIG_FILE=/app/rasp_config.yaml
      - RASP_BACKEND_URL=http://rasp-backend:8000
    volumes:
      - ./logs:/var/log/cybershield
    depends_on:
      - rasp-backend
      - postgres
      - redis

  rasp-backend:
    image: cybershield/rasp-backend:latest
    ports:
      - "8001:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/cybershield
      - REDIS_URL=redis://redis:6379/0

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=cybershield
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    command: redis-server --requirepass redis_password

volumes:
  postgres_data:
```

## Language-Specific Configuration

### Python Applications

#### Advanced Python Hooks

```python
# Custom Python hooks for specific frameworks
from rasp_agent import RASPAgent, Hook

# Django-specific hooks
@Hook("django.db.models.query.QuerySet.filter")
def django_query_hook(func, *args, **kwargs):
    # Monitor Django ORM queries
    query = str(args[0]) if args else ""
    if "SELECT" in query.upper() and any(char in query for char in ["'", '"', ";"]):
        RASPAgent.report_attack("sql_injection", query, severity="critical")
    return func(*args, **kwargs)

# Flask-specific hooks
@Hook("flask.request.args.get")
def flask_args_hook(func, key, default=None, type=None):
    # Monitor Flask request arguments
    value = func(key, default, type)
    if value and any(pattern in value for pattern in ["<script>", "javascript:"]):
        RASPAgent.report_attack("xss", value, severity="high")
    return value
```

### Java Applications

#### Spring Boot Security Integration

```java
// RASPSecurityConfig.java
package com.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import com.cybershield.rasp.security.RASPSecurityFilter;

@Configuration
@EnableWebSecurity
public class RASPSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .addFilterBefore(new RASPSecurityFilter(), UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests()
            .anyRequest().authenticated();
        return http.build();
    }
}
```

### Node.js Applications

#### Express.js Integration

```javascript
// app.js
const express = require('express');
const raspAgent = require('@cybershield/rasp-agent');

const app = express();

// Initialize RASP agent
raspAgent.initialize({
    agentName: 'nodejs-app-prod-01',
    language: 'nodejs',
    version: '1.0.0',
    environment: 'production',
    backendUrl: 'http://localhost:8000',
    apiKey: 'your-api-key-here',
    config: {
        monitoring: {
            database: {
                enabled: true,
                hooks: ['mysql2', 'pg', 'mongodb']
            },
            filesystem: {
                enabled: true,
                hooks: ['fs', 'path']
            },
            command: {
                enabled: true,
                hooks: ['child_process']
            }
        }
    }
});

// RASP middleware
app.use(raspAgent.middleware());

app.get('/api/users', (req, res) => {
    // This will be monitored automatically
    const userId = req.query.id;
    // ... database query
});

app.listen(3000);
```

## Detection Rules Setup

### 1. Default Rules Configuration

```yaml
# detection_rules.yaml
rules:
  # SQL Injection Rules
  - name: "sql_injection_basic"
    type: "sql_injection"
    pattern: ".*SELECT.*FROM.*\\+.*"
    severity: "critical"
    auto_block: true
    description: "Basic SQL injection detection"
    
  - name: "sql_injection_union"
    type: "sql_injection"
    pattern: ".*UNION.*SELECT.*"
    severity: "critical"
    auto_block: true
    description: "UNION-based SQL injection"
    
  # Command Injection Rules
  - name: "command_injection_semicolon"
    type: "command_injection"
    pattern: ".*;.*"
    severity: "critical"
    auto_block: true
    description: "Command injection with semicolon"
    
  - name: "command_injection_pipe"
    type: "command_injection"
    pattern: ".*\\|.*"
    severity: "critical"
    auto_block: true
    description: "Command injection with pipe"
    
  # Path Traversal Rules
  - name: "path_traversal_dots"
    type: "path_traversal"
    pattern: ".*\\.\\./.*"
    severity: "high"
    auto_block: true
    description: "Path traversal with ../"
    
  # XSS Rules
  - name: "xss_script_tag"
    type: "xss"
    pattern: ".*<script.*>.*"
    severity: "high"
    auto_block: true
    description: "XSS with script tag"
    
  - name: "xss_javascript"
    type: "xss"
    pattern: ".*javascript:.*"
    severity: "high"
    auto_block: true
    description: "XSS with javascript: protocol"
```

### 2. Custom Rules Creation

```python
# custom_rules.py
from rasp_agent import DetectionRule

# Custom rule for business logic
class CustomBusinessRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="custom_business_rule",
            rule_type="business_logic",
            severity="medium",
            auto_block=False
        )
    
    def evaluate(self, context):
        # Custom business logic evaluation
        if context.get('user_role') == 'admin' and context.get('action') == 'delete_all':
            return True, "Suspicious admin action detected"
        return False, None

# Register custom rule
RASPAgent.register_rule(CustomBusinessRule())
```

## SIEM/SOAR Integration

### 1. Splunk Integration

```python
# splunk_integration.py
import requests
import json
from datetime import datetime

class SplunkIntegration:
    def __init__(self, splunk_url, token):
        self.splunk_url = splunk_url
        self.token = token
        self.headers = {
            'Authorization': f'Splunk {token}',
            'Content-Type': 'application/json'
        }
    
    def send_event(self, event_data):
        """Send RASP event to Splunk"""
        event = {
            'event': event_data,
            'sourcetype': 'rasp_attack',
            'source': 'cybershield_rasp',
            'time': datetime.utcnow().isoformat()
        }
        
        response = requests.post(
            f"{self.splunk_url}/services/collector/event",
            headers=self.headers,
            json=event
        )
        return response.status_code == 200
```

### 2. QRadar Integration

```python
# qradar_integration.py
import requests
import json

class QRadarIntegration:
    def __init__(self, qradar_url, token):
        self.qradar_url = qradar_url
        self.token = token
        self.headers = {
            'SEC': token,
            'Content-Type': 'application/json'
        }
    
    def send_offense(self, attack_data):
        """Send RASP attack to QRadar as offense"""
        offense = {
            'description': f"RASP Attack: {attack_data['type']}",
            'magnitude': self._get_magnitude(attack_data['severity']),
            'credibility': 10,
            'relevance': 10,
            'source_network': attack_data.get('source_ip', 'unknown'),
            'offense_source': 'cybershield_rasp'
        }
        
        response = requests.post(
            f"{self.qradar_url}/api/siem/offenses",
            headers=self.headers,
            json=offense
        )
        return response.status_code == 201
    
    def _get_magnitude(self, severity):
        severity_map = {
            'low': 1,
            'medium': 3,
            'high': 7,
            'critical': 10
        }
        return severity_map.get(severity, 5)
```

### 3. Cortex XSOAR Integration

```python
# cortex_integration.py
import requests
import json

class CortexXSOARIntegration:
    def __init__(self, cortex_url, api_key):
        self.cortex_url = cortex_url
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_incident(self, attack_data):
        """Create incident in Cortex XSOAR"""
        incident = {
            'name': f"RASP Attack: {attack_data['type']}",
            'type': 'RASP Attack',
            'severity': self._map_severity(attack_data['severity']),
            'details': attack_data.get('description', ''),
            'source_ip': attack_data.get('source_ip', 'unknown'),
            'custom_fields': {
                'rasp_attack_type': attack_data['type'],
                'rasp_payload': attack_data.get('payload', ''),
                'rasp_blocked': attack_data.get('blocked', False)
            }
        }
        
        response = requests.post(
            f"{self.cortex_url}/incident",
            headers=self.headers,
            json=incident
        )
        return response.status_code == 201
    
    def _map_severity(self, rasp_severity):
        severity_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_map.get(rasp_severity, 2)
```

## Monitoring and Tuning

### 1. Performance Monitoring

```python
# performance_monitor.py
import psutil
import time
from rasp_agent import RASPAgent

class PerformanceMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.attack_count = 0
        self.blocked_count = 0
    
    def collect_metrics(self):
        """Collect performance metrics"""
        metrics = {
            'timestamp': time.time(),
            'uptime': time.time() - self.start_time,
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'attack_count': self.attack_count,
            'blocked_count': self.blocked_count,
            'block_rate': self.blocked_count / max(self.attack_count, 1) * 100
        }
        
        # Send metrics to RASP backend
        RASPAgent.send_telemetry(metrics)
        return metrics
    
    def record_attack(self, blocked=False):
        """Record attack occurrence"""
        self.attack_count += 1
        if blocked:
            self.blocked_count += 1
```

### 2. Alert Configuration

```yaml
# alerts.yaml
alerts:
  # High attack rate alert
  - name: "high_attack_rate"
    condition: "attack_count > 100 in 5 minutes"
    severity: "high"
    actions:
      - "email:security@company.com"
      - "slack:#security-alerts"
      - "webhook:https://api.company.com/security/alert"
  
  # Critical attack alert
  - name: "critical_attack"
    condition: "attack_severity == 'critical'"
    severity: "critical"
    actions:
      - "email:security@company.com"
      - "sms:+1234567890"
      - "webhook:https://api.company.com/security/critical"
  
  # Performance degradation alert
  - name: "performance_degradation"
    condition: "response_time > 5 seconds"
    severity: "medium"
    actions:
      - "email:ops@company.com"
      - "slack:#ops-alerts"
```

### 3. Log Analysis

```bash
# Analyze RASP logs
#!/bin/bash

# Count attacks by type
grep "attack_detected" /var/log/cybershield/rasp-agent.log | \
  jq -r '.attack_type' | sort | uniq -c

# Count blocked vs allowed attacks
grep "attack_detected" /var/log/cybershield/rasp-agent.log | \
  jq -r '.blocked' | sort | uniq -c

# Top source IPs
grep "attack_detected" /var/log/cybershield/rasp-agent.log | \
  jq -r '.source_ip' | sort | uniq -c | sort -nr | head -10

# Performance metrics
grep "telemetry" /var/log/cybershield/rasp-agent.log | \
  jq -r '.cpu_usage, .memory_usage, .response_time' | \
  awk '{sum+=$1; count++} END {print "Average:", sum/count}'
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Agent Not Starting

**Symptoms**: Agent fails to start or connect to backend

**Solutions**:
```bash
# Check network connectivity
curl -f http://localhost:8000/health

# Check configuration file
python3 -c "import yaml; yaml.safe_load(open('rasp_config.yaml'))"

# Check logs
tail -f /var/log/cybershield/rasp-agent.log

# Test database connection
psql -h localhost -U cybershield_user -d cybershield -c "SELECT 1;"
```

#### 2. High False Positives

**Symptoms**: Too many false positive alerts

**Solutions**:
```yaml
# Adjust detection sensitivity
detection:
  sql_injection:
    enabled: true
    patterns:
      # More specific patterns
      - ".*SELECT.*FROM.*\\+.*WHERE.*"
      - ".*UNION.*SELECT.*FROM.*"
    severity: "critical"
    auto_block: false  # Start with logging only
```

#### 3. Performance Impact

**Symptoms**: Application performance degradation

**Solutions**:
```yaml
# Optimize monitoring
monitoring:
  database:
    enabled: true
    hooks:
      # Only monitor critical database operations
      - "psycopg2.connect"
      - "mysql.connector.connect"
  
  # Disable non-critical monitoring
  filesystem:
    enabled: false  # Disable if not needed
  
  # Reduce telemetry frequency
telemetry:
  interval: 300  # Increase to 5 minutes
```

#### 4. Memory Leaks

**Symptoms**: Increasing memory usage over time

**Solutions**:
```python
# Implement proper cleanup
import atexit
from rasp_agent import RASPAgent

def cleanup():
    """Cleanup RASP agent resources"""
    RASPAgent.shutdown()

atexit.register(cleanup)
```

### Debug Mode

```yaml
# Enable debug mode for troubleshooting
logging:
  level: "DEBUG"
  file: "/var/log/cybershield/rasp-agent-debug.log"
  max_size: "50MB"
  backup_count: 10

debug:
  enabled: true
  verbose_hooks: true
  performance_tracking: true
  memory_profiling: true
```

### Health Check Script

```bash
#!/bin/bash
# health_check.sh

echo "=== RASP Agent Health Check ==="

# Check if agent is running
if pgrep -f "rasp_agent" > /dev/null; then
    echo "✅ RASP agent is running"
else
    echo "❌ RASP agent is not running"
fi

# Check backend connectivity
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Backend is accessible"
else
    echo "❌ Backend is not accessible"
fi

# Check database connectivity
if PGPASSWORD=cybershield_password psql -h localhost -U cybershield_user -d cybershield -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Database is accessible"
else
    echo "❌ Database is not accessible"
fi

# Check log file
if [[ -f "/var/log/cybershield/rasp-agent.log" ]]; then
    echo "✅ Log file exists"
    echo "Last 10 log entries:"
    tail -10 /var/log/cybershield/rasp-agent.log
else
    echo "❌ Log file does not exist"
fi

echo "=== Health Check Complete ==="
```

## Conclusion

This guide provides comprehensive instructions for configuring RASP agents across different platforms and languages. The key to successful deployment is:

1. **Start Small**: Begin with basic monitoring and gradually enable more features
2. **Monitor Performance**: Watch for performance impact and adjust accordingly
3. **Tune Rules**: Start with logging only, then enable blocking after tuning
4. **Integrate Monitoring**: Connect to your existing SIEM/SOAR infrastructure
5. **Regular Maintenance**: Monitor logs, update rules, and optimize performance

For additional support and advanced configurations, refer to the RASP documentation and implementation guides. 