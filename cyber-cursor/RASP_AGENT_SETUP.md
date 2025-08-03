# RASP Agent Setup Guide

## Quick Start

### 1. Deploy RASP Backend

```bash
# Windows (PowerShell)
.\deploy-rasp-backend.ps1 -Environment production

# Linux/macOS
chmod +x deploy-rasp-backend.sh
./deploy-rasp-backend.sh --environment production
```

### 2. Configure Agents

#### Python Applications

```bash
# Install RASP agent
pip install cybershield-rasp-agent

# Create configuration
cat > rasp_config.yaml << EOF
agent:
  name: "web-app-01"
  language: "python"
  environment: "production"

backend:
  api_url: "http://localhost:8000"
  api_key: "your-api-key"

monitoring:
  database: true
  filesystem: true
  command: true
  network: true

detection:
  sql_injection:
    enabled: true
    auto_block: true
  command_injection:
    enabled: true
    auto_block: true
  path_traversal:
    enabled: true
    auto_block: true
EOF

# Integrate with your app
python -c "
from rasp_agent import RASPAgent
RASPAgent.initialize('rasp_config.yaml')
"
```

#### Java Applications

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.cybershield</groupId>
    <artifactId>rasp-agent</artifactId>
    <version>1.0.0</version>
</dependency>
```

```java
// Application.java
import com.cybershield.rasp.RASPAgent;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        RASPAgent.initialize();
        SpringApplication.run(Application.class, args);
    }
}
```

#### Node.js Applications

```bash
npm install @cybershield/rasp-agent
```

```javascript
// app.js
const raspAgent = require('@cybershield/rasp-agent');

raspAgent.initialize({
    agentName: 'nodejs-app-01',
    backendUrl: 'http://localhost:8000',
    apiKey: 'your-api-key'
});

app.use(raspAgent.middleware());
```

### 3. Set Up Detection Rules

```bash
# Create custom rules
curl -X POST http://localhost:8000/api/rasp/rules \
  -H "Content-Type: application/json" \
  -d '{
    "rule_type": "sql_injection",
    "pattern": ".*SELECT.*FROM.*\\+.*",
    "severity": "critical",
    "auto_block": true,
    "description": "SQL injection detection"
  }'
```

### 4. Configure SIEM Integration

```bash
# Splunk integration
curl -X POST http://localhost:8000/api/rasp/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "splunk",
    "type": "splunk",
    "url": "https://splunk.company.com:8088",
    "token": "your-splunk-token",
    "enabled": true
  }'

# QRadar integration
curl -X POST http://localhost:8000/api/rasp/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "qradar",
    "type": "qradar",
    "url": "https://qradar.company.com",
    "token": "your-qradar-token",
    "enabled": true
  }'
```

### 5. Monitor and Tune

```bash
# Check agent status
curl http://localhost:8000/api/rasp/agents

# View attacks
curl http://localhost:8000/api/rasp/attacks

# Dashboard overview
curl http://localhost:8000/api/rasp/dashboard/overview

# Run test suite
python test-rasp.py
```

## Platform-Specific Configuration

### Windows

```powershell
# Install as Windows Service
New-Service -Name "RASP-Agent" -BinaryPathName "python.exe C:\path\to\rasp-agent.py"

# Start service
Start-Service "RASP-Agent"

# Check status
Get-Service "RASP-Agent"
```

### Linux

```bash
# Create systemd service
sudo tee /etc/systemd/system/rasp-agent.service << EOF
[Unit]
Description=RASP Agent
After=network.target

[Service]
Type=simple
User=rasp
ExecStart=/usr/bin/python3 /opt/rasp-agent/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable rasp-agent
sudo systemctl start rasp-agent
sudo systemctl status rasp-agent
```

### Docker

```dockerfile
# Dockerfile
FROM python:3.9-slim
RUN pip install cybershield-rasp-agent
COPY app.py /app/
COPY rasp_config.yaml /app/
WORKDIR /app
CMD ["python", "-m", "rasp_agent", "app.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  web-app:
    build: .
    environment:
      - RASP_CONFIG_FILE=/app/rasp_config.yaml
    volumes:
      - ./logs:/var/log/cybershield
```

## Security Requirements

### Network Security
- HTTPS for all communications
- API key authentication
- IP whitelisting (optional)
- Firewall rules for agent-backend communication

### Access Control
- Least privilege principle
- Service account for agents
- Read-only access to application logs
- Encrypted configuration files

### Monitoring
- Agent heartbeat monitoring
- Performance impact monitoring
- False positive rate tracking
- Attack pattern analysis

## Troubleshooting

### Common Issues

1. **Agent not connecting to backend**
   ```bash
   # Check network connectivity
   curl -f http://localhost:8000/health
   
   # Check configuration
   python -c "import yaml; yaml.safe_load(open('rasp_config.yaml'))"
   ```

2. **High false positives**
   ```yaml
   # Start with logging only
   detection:
     sql_injection:
       auto_block: false  # Log only initially
   ```

3. **Performance impact**
   ```yaml
   # Reduce monitoring scope
   monitoring:
     filesystem: false  # Disable if not needed
   telemetry:
     interval: 300  # Increase interval
   ```

### Debug Mode

```yaml
# Enable debug logging
logging:
  level: "DEBUG"
  file: "/var/log/cybershield/rasp-agent-debug.log"

debug:
  enabled: true
  verbose_hooks: true
```

### Health Check

```bash
#!/bin/bash
# health_check.sh

echo "=== RASP Health Check ==="

# Check agent process
pgrep -f "rasp_agent" && echo "✅ Agent running" || echo "❌ Agent not running"

# Check backend
curl -f http://localhost:8000/health && echo "✅ Backend OK" || echo "❌ Backend failed"

# Check logs
tail -5 /var/log/cybershield/rasp-agent.log
```

## Next Steps

1. **Deploy agents** to your applications
2. **Configure detection rules** based on your security requirements
3. **Integrate with SIEM/SOAR** systems
4. **Monitor and tune** based on real-world usage
5. **Set up alerts** for critical attacks
6. **Regular maintenance** and rule updates

## Documentation

- [RASP README](RASP_README.md)
- [Implementation Document](RASP_IMPLEMENTATION_DOCUMENT.md)
- [Test Script](test-rasp.py)
- [API Documentation](http://localhost:8000/docs) 