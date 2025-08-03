# RASP (Runtime Application Self-Protection) Tool

## Overview

The RASP (Runtime Application Self-Protection) tool is a comprehensive security solution that provides real-time monitoring and protection for applications during runtime. It combines the best features from Contrast Security and Imperva, offering inline threat detection, automatic blocking, and deep visibility into application behavior.

## Key Features

### 🛡️ Real-Time Threat Detection & Blocking
- **Inline Monitoring**: Monitors requests and responses at runtime
- **Automatic Blocking**: Detects and blocks attacks without network-level devices
- **Vulnerability Types**: SQL Injection, XSS, Command Injection, Path Traversal, Deserialization Attacks
- **Zero-day Protection**: Detects logic-based and unknown attack patterns

### 🔍 Context-Aware Protection
- **Deep Visibility**: Monitors code execution, libraries, and system calls
- **Precise Detection**: Knows the vulnerable line of code, affected method, and parameter
- **Low False Positives**: Context-aware analysis reduces false alarms

### 🔧 Application-Level Instrumentation
- **Multi-Language Support**: Java, .NET, Python, Node.js agents
- **Runtime Hooks**: Integrates with application runtime (JVM, CLR, Python interpreter)
- **Virtual Patching**: Temporary fixes without code changes

### 📊 Advanced Logging & Telemetry
- **Detailed Context**: Source IP, user, HTTP request, stack trace, vulnerable file/line
- **Centralized Dashboard**: Real-time vulnerability feed and blocked attacks
- **SIEM/SOAR Integration**: Splunk, QRadar, Cortex XSOAR support

### 🤖 Machine Learning & Behavior Analysis
- **Anomaly Detection**: Identifies patterns signature-based detection misses
- **Threat Prioritization**: Automatically prioritizes based on real exploitability
- **Self-Healing**: Auto-sanitization of malicious payloads

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Native Dashboard                    │
│  • Vulnerability Feed • Blocked Attacks • Reports & Alerts  │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Backend (Python FastAPI)                  │
│  • Attack Logging & Rule Engine • Virtual Patching Engine   │
│  • Report Generator • SIEM Integration                      │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                      Data Storage                           │
│  • PostgreSQL → Attacks, Vulnerabilities, Agents           │
│  • Redis/Kafka → Event Queue for High Volume              │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                Runtime Agents (Java/Python/Node)            │
│  • Hooks into sensitive functions (DB, File, Command)      │
│  • Detects, Blocks & Logs attacks inline                   │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Redis (optional, for caching)
- Node.js 16+ (for React Native frontend)

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cyber-cursor
   ```

2. **Install Python dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Set up the database**
   ```bash
   # Initialize RASP database schema
   psql -U your_user -d your_database -f scripts/init-rasp-db.sql
   ```

4. **Configure environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your database and other settings
   ```

5. **Run the backend**
   ```bash
   python main.py
   ```

### Frontend Setup

1. **Install React Native dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Start the development server**
   ```bash
   npm start
   ```

## Usage

### Web Dashboard

Access the RASP dashboard at `http://localhost:3000` to:
- Monitor agent status and health
- View real-time attack feed
- Manage detection rules
- Configure virtual patches
- Generate reports

### API Usage

#### Agent Management

```bash
# Create a new agent
curl -X POST "http://localhost:8000/api/rasp/agents" \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "My Web App",
    "language": "python",
    "version": "1.0.0",
    "config": {"monitoring_level": "high"}
  }'

# Get all agents
curl "http://localhost:8000/api/rasp/agents"

# Update agent heartbeat
curl -X POST "http://localhost:8000/api/rasp/agents/1/heartbeat" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "active",
    "telemetry": [
      {
        "metric_name": "requests_per_minute",
        "metric_value": 150
      }
    ]
  }'
```

#### Attack Monitoring

```bash
# Get recent attacks
curl "http://localhost:8000/api/rasp/attacks?hours=24"

# Get attack summary
curl "http://localhost:8000/api/rasp/dashboard/attack-summary"

# Create attack record (typically called by agents)
curl -X POST "http://localhost:8000/api/rasp/attacks" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": 1,
    "source_ip": "192.168.1.100",
    "url": "/api/users",
    "payload": "'; DROP TABLE users; --",
    "vuln_type": "SQLi",
    "severity": "critical",
    "blocked": true
  }'
```

#### Rule Management

```bash
# Get detection rules
curl "http://localhost:8000/api/rasp/rules?language=python"

# Create a new rule
curl -X POST "http://localhost:8000/api/rasp/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_type": "SQLi",
    "language": "python",
    "pattern": ".*SELECT.*FROM.*\\+.*",
    "severity": "critical",
    "auto_block": true,
    "description": "Detect concatenated SQL with untrusted input"
  }'

# Update rule
curl -X PUT "http://localhost:8000/api/rasp/rules/1" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

#### Vulnerability Management

```bash
# Get vulnerabilities
curl "http://localhost:8000/api/rasp/vulnerabilities?status=open"

# Update vulnerability status
curl -X PUT "http://localhost:8000/api/rasp/vulnerabilities/1" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved",
    "remediation": "Use parameterized queries"
  }'
```

#### Virtual Patching

```bash
# Create virtual patch
curl -X POST "http://localhost:8000/api/rasp/virtual-patches" \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_id": 1,
    "agent_id": 1,
    "patch_type": "input_validation",
    "patch_config": {
      "pattern": ".*(;|&&).*",
      "replacement": ""
    }
  }'
```

### CLI Tool

```bash
# Install RASP CLI
pip install -e .

# Get dashboard overview
rasp-cli dashboard overview

# List agents
rasp-cli agents list

# Get recent attacks
rasp-cli attacks list --hours 24

# Create rule
rasp-cli rules create --vuln-type SQLi --language python --pattern ".*SELECT.*FROM.*\\+.*"

# Validate payload
rasp-cli rules validate --payload "'; DROP TABLE users; --" --language python
```

## Configuration

### Agent Configuration

```json
{
  "monitoring_level": "high",
  "auto_block": true,
  "telemetry_interval": 60,
  "rules_update_interval": 300,
  "excluded_paths": ["/health", "/metrics"],
  "sensitive_functions": [
    "os.system",
    "subprocess.call",
    "eval",
    "exec"
  ]
}
```

### Detection Rules

The system comes with pre-configured rules for common vulnerabilities:

#### SQL Injection (CWE-89)
```json
{
  "vuln_type": "SQLi",
  "language": "python",
  "pattern": ".*SELECT.*FROM.*\\+.*",
  "severity": "critical",
  "auto_block": true,
  "description": "Detect concatenated SQL with untrusted input"
}
```

#### Command Injection (CWE-77)
```json
{
  "vuln_type": "Command Injection",
  "language": "python",
  "pattern": ".*(;|&&|\\|\\||`).*",
  "severity": "critical",
  "auto_block": true,
  "description": "Block if input contains shell operators"
}
```

#### Path Traversal (CWE-22)
```json
{
  "vuln_type": "Path Traversal",
  "language": "python",
  "pattern": ".*\\.\\./.*",
  "severity": "high",
  "auto_block": true,
  "description": "Block if path contains directory traversal sequences"
}
```

## Database Schema

### Key Tables

#### `rasp_agents`
- Agent registration and status
- Application metadata and configuration
- Last seen timestamp and health status

#### `rasp_attacks`
- Detected attack records
- Payload, context, and blocking status
- Request/response data for analysis

#### `rasp_rules`
- Detection rule definitions
- Pattern matching and severity levels
- Auto-blocking configuration

#### `rasp_vulnerabilities`
- Discovered vulnerabilities
- Affected code locations and remediation
- Status tracking and evidence

#### `rasp_virtual_patches`
- Temporary vulnerability fixes
- Patch configuration and expiration
- Agent-specific patch deployment

## Security Considerations

### Data Protection
- **Encryption at Rest**: All sensitive data encrypted with AES-256
- **TLS 1.2/1.3**: Secure communication between components
- **Access Control**: Role-based access control (RBAC)
- **Audit Logging**: Comprehensive audit trail for all operations

### Agent Security
- **Secure Communication**: Agents use TLS for API communication
- **Authentication**: API key-based authentication for agents
- **Configuration Validation**: All agent configurations validated
- **Isolation**: Agents run in isolated environments

### Rule Management
- **Validation**: All rules validated before deployment
- **Testing**: Rule testing framework for false positive reduction
- **Versioning**: Rule versioning and rollback capabilities
- **Approval Workflow**: Multi-stage approval for rule changes

## Performance Optimization

### High-Volume Handling
- **Asynchronous Processing**: Non-blocking attack detection
- **Connection Pooling**: Database connection optimization
- **Caching**: Redis-based caching for frequently accessed data
- **Batch Processing**: Bulk operations for telemetry data

### Scalability
- **Horizontal Scaling**: Multiple backend instances
- **Load Balancing**: Distributed agent load
- **Database Sharding**: Partitioned data storage
- **Message Queues**: Kafka/Redis for event processing

## Monitoring and Alerting

### Metrics Collection
- **Performance Metrics**: Response times, throughput
- **Security Metrics**: Attack rates, blocking effectiveness
- **Agent Metrics**: Health status, telemetry data
- **System Metrics**: Resource utilization, error rates

### Alerting
- **Real-time Alerts**: Immediate notification of critical events
- **Escalation**: Automated escalation for high-severity issues
- **Integration**: Email, Slack, PagerDuty integration
- **Custom Rules**: Configurable alert thresholds

## Troubleshooting

### Common Issues

#### Agent Connection Problems
```bash
# Check agent status
curl "http://localhost:8000/api/rasp/agents/1"

# View agent logs
docker logs rasp-agent-1

# Test agent connectivity
rasp-cli agents test-connection --agent-id 1
```

#### Rule Validation Issues
```bash
# Test rule pattern
rasp-cli rules test --pattern ".*SELECT.*FROM.*\\+.*" --payload "SELECT * FROM users + 'test'"

# Validate rule syntax
rasp-cli rules validate-syntax --rule-file rules.json
```

#### Performance Issues
```bash
# Check system metrics
rasp-cli system metrics

# Analyze slow queries
rasp-cli database analyze --slow-queries

# Monitor resource usage
rasp-cli system monitor --cpu --memory --disk
```

### Log Analysis

```bash
# View application logs
tail -f logs/rasp.log

# Search for specific errors
grep "ERROR" logs/rasp.log | tail -20

# Analyze attack patterns
rasp-cli attacks analyze --pattern "SQLi" --hours 24
```

## Development

### Adding New Vulnerability Types

1. **Define the vulnerability type**
   ```python
   # In app/models/rasp.py
   class VulnerabilityType(str, Enum):
       NEW_VULN_TYPE = "new_vuln_type"
   ```

2. **Create detection rules**
   ```sql
   INSERT INTO rasp_rules (vuln_type, language, pattern, severity, auto_block, description)
   VALUES ('new_vuln_type', 'python', '.*pattern.*', 'high', true, 'Description');
   ```

3. **Update agent detection logic**
   ```python
   # In agent detection code
   if re.search(pattern, payload):
       await report_vulnerability('new_vuln_type', payload, context)
   ```

### Custom Integrations

```python
# Example SIEM integration
class CustomSIEMIntegration:
    def __init__(self, config):
        self.endpoint = config['endpoint']
        self.api_key = config['api_key']
    
    async def send_alert(self, attack_data):
        payload = {
            'event_type': 'rasp_attack',
            'timestamp': datetime.utcnow().isoformat(),
            'data': attack_data
        }
        
        async with aiohttp.ClientSession() as session:
            await session.post(
                self.endpoint,
                json=payload,
                headers={'Authorization': f'Bearer {self.api_key}'}
            )
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 backend/
black backend/

# Run type checking
mypy backend/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Documentation**: [Link to documentation]
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Email**: support@your-company.com

## Roadmap

### Phase 1: Core RASP Agent ✅
- [x] Language-specific runtime hooks
- [x] Basic attack detection
- [x] Agent management

### Phase 2: Detection & Blocking Engine ✅
- [x] Rule-based detection
- [x] Inline blocking
- [x] Pattern matching

### Phase 3: Dashboard & Reporting ✅
- [x] Web dashboard
- [x] Real-time monitoring
- [x] Report generation

### Phase 4: CI/CD & DevSecOps Integration 🚧
- [ ] Pipeline integration
- [ ] Auto virtual patching
- [ ] Deployment blocking

### Phase 5: Advanced Functions 📋
- [ ] ML-based anomaly detection
- [ ] Self-healing runtime
- [ ] SAST/DAST/SIEM correlation
- [ ] Advanced threat intelligence

## Acknowledgments

- Inspired by Contrast Security and Imperva RASP solutions
- Built with FastAPI, React Native, and PostgreSQL
- Community contributions and feedback 