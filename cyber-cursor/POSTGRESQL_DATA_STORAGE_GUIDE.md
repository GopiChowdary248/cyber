# PostgreSQL Data Storage Guide for CyberShield

## 🗄️ Database Overview

The CyberShield application uses PostgreSQL to store cybersecurity data. The database contains multiple tables for different security modules.

### **Current Database Tables:**
- `users` - User accounts and authentication
- `sast_projects` - Static Application Security Testing projects
- `sast_scans` - SAST scan results
- `sast_reports` - SAST scan reports
- `sast_vulnerabilities` - Detected vulnerabilities
- `dast_projects` - Dynamic Application Security Testing projects
- `dast_scans` - DAST scan results
- `rasp_agents` - Runtime Application Self-Protection agents
- `rasp_alerts` - RASP security alerts
- `rasp_attacks` - Attack attempts detected by RASP
- `rasp_integrations` - RASP integrations
- `rasp_rules` - RASP security rules
- `rasp_telemetry` - RASP telemetry data
- `rasp_vulnerabilities` - RASP detected vulnerabilities
- `rasp_virtual_patches` - RASP virtual patches

## 📊 Sample Data Already Stored

### **Users Table:**
```sql
-- Current users in the system
SELECT id, email, username, role, department FROM users;

-- Results:
-- 1 | admin@cybershield.com   | admin    | admin   | IT Security
-- 2 | analyst@cybershield.com | analyst  | analyst | Security Operations  
-- 3 | user@cybershield.com    | user     | user    | General
```

### **SAST Projects Table:**
```sql
-- Current SAST projects
SELECT id, name, language, security_score, is_active FROM sast_projects;

-- Results include:
-- Web Application Security (Python, Score: 8.5)
-- Mobile App Security (JavaScript, Score: 7.8)
-- API Security Testing (Python, Score: 9.2)
```

## 🔧 Methods to Store Data

### **1. Direct SQL Commands**

#### **Connect to Database:**
```bash
# Connect to PostgreSQL container
docker-compose exec postgres psql -U cybershield_user -d cybershield
```

#### **Insert User Data:**
```sql
INSERT INTO users (
    email, 
    username, 
    full_name, 
    hashed_password, 
    role, 
    is_active, 
    is_verified, 
    department, 
    phone
) VALUES (
    'newuser@company.com',
    'newuser',
    'New User',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2',
    'user',
    true,
    true,
    'Development',
    '+1-555-0104'
);
```

#### **Insert SAST Project:**
```sql
INSERT INTO sast_projects (
    id,
    name,
    description,
    repository_url,
    language,
    total_scans,
    avg_vulnerabilities,
    security_score,
    is_active,
    created_by
) VALUES (
    gen_random_uuid(),
    'Project Name',
    'Project Description',
    'https://github.com/company/project',
    'Python',
    0,
    0.0,
    8.0,
    true,
    1
);
```

### **2. Using API Endpoints**

#### **Create User via API:**
```bash
curl -X POST "http://localhost:8000/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "apiuser@company.com",
    "username": "apiuser",
    "full_name": "API User",
    "password": "securepassword",
    "role": "user",
    "department": "Development"
  }'
```

#### **Create SAST Project via API:**
```bash
curl -X POST "http://localhost:8000/api/v1/sast/projects" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Created Project",
    "description": "Project created via API",
    "repository_url": "https://github.com/company/apiproject",
    "language": "Python"
  }'
```

### **3. Using Python Scripts**

#### **Create a Python script to insert data:**
```python
import psycopg2
import uuid
from datetime import datetime

# Database connection
conn = psycopg2.connect(
    host="localhost",
    port="5432",
    database="cybershield",
    user="cybershield_user",
    password="cybershield_password"
)

cursor = conn.cursor()

# Insert user
cursor.execute("""
    INSERT INTO users (email, username, full_name, hashed_password, role, is_active, is_verified, department)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
""", (
    'pythonuser@company.com',
    'pythonuser',
    'Python User',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2',
    'user',
    True,
    True,
    'Development'
))

# Insert SAST project
project_id = str(uuid.uuid4())
cursor.execute("""
    INSERT INTO sast_projects (id, name, description, repository_url, language, total_scans, avg_vulnerabilities, security_score, is_active, created_by)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
""", (
    project_id,
    'Python Created Project',
    'Project created via Python script',
    'https://github.com/company/pythonproject',
    'Python',
    0,
    0.0,
    8.5,
    True,
    1
))

conn.commit()
cursor.close()
conn.close()
```

## 📋 Data Storage Examples

### **1. Store Security Scan Results:**
```sql
-- Insert SAST scan
INSERT INTO sast_scans (
    id,
    project_id,
    scan_type,
    status,
    start_time,
    end_time,
    total_files_scanned,
    total_vulnerabilities,
    critical_count,
    high_count,
    medium_count,
    low_count,
    scan_duration,
    created_by
) VALUES (
    gen_random_uuid(),
    (SELECT id FROM sast_projects WHERE name = 'Web Application Security' LIMIT 1),
    'full',
    'completed',
    NOW() - INTERVAL '1 hour',
    NOW(),
    150,
    5,
    1,
    2,
    1,
    1,
    1800,
    1
);
```

### **2. Store Vulnerability Data:**
```sql
-- Insert vulnerability
INSERT INTO sast_vulnerabilities (
    id,
    scan_id,
    vulnerability_type,
    severity,
    file_path,
    line_number,
    description,
    recommendation,
    cwe_id,
    cvss_score,
    status
) VALUES (
    gen_random_uuid(),
    (SELECT id FROM sast_scans ORDER BY created_at DESC LIMIT 1),
    'SQL Injection',
    'high',
    '/app/database.py',
    45,
    'Potential SQL injection vulnerability detected',
    'Use parameterized queries instead of string concatenation',
    'CWE-89',
    8.5,
    'open'
);
```

### **3. Store RASP Data:**
```sql
-- Insert RASP agent
INSERT INTO rasp_agents (
    id,
    agent_name,
    agent_type,
    version,
    status,
    last_heartbeat,
    configuration,
    created_at
) VALUES (
    gen_random_uuid(),
    'web-app-agent-01',
    'web',
    '1.2.3',
    'active',
    NOW(),
    '{"protection_level": "high", "monitoring": true}',
    NOW()
);
```

## 🔍 Querying Stored Data

### **Basic Queries:**
```sql
-- Get all active users
SELECT id, email, username, role, department 
FROM users 
WHERE is_active = true;

-- Get all SAST projects with security scores
SELECT name, language, security_score, total_scans 
FROM sast_projects 
WHERE is_active = true 
ORDER BY security_score DESC;

-- Get recent scan results
SELECT p.name, s.scan_type, s.status, s.total_vulnerabilities, s.scan_duration
FROM sast_scans s
JOIN sast_projects p ON s.project_id = p.id
ORDER BY s.start_time DESC
LIMIT 10;
```

### **Advanced Queries:**
```sql
-- Get vulnerability statistics by project
SELECT 
    p.name,
    COUNT(v.id) as total_vulnerabilities,
    AVG(v.cvss_score) as avg_cvss_score,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high_count
FROM sast_projects p
LEFT JOIN sast_scans s ON p.id = s.project_id
LEFT JOIN sast_vulnerabilities v ON s.id = v.scan_id
GROUP BY p.id, p.name
ORDER BY total_vulnerabilities DESC;

-- Get user activity summary
SELECT 
    u.username,
    u.department,
    COUNT(s.id) as scans_created,
    MAX(s.created_at) as last_scan
FROM users u
LEFT JOIN sast_scans s ON u.id = s.created_by
GROUP BY u.id, u.username, u.department
ORDER BY scans_created DESC;
```

## 🛠️ Database Management Commands

### **Backup Database:**
```bash
# Create backup
docker-compose exec postgres pg_dump -U cybershield_user cybershield > backup.sql

# Restore from backup
docker-compose exec -T postgres psql -U cybershield_user -d cybershield < backup.sql
```

### **Reset Database:**
```bash
# Drop and recreate database
docker-compose exec postgres psql -U cybershield_user -c "DROP DATABASE cybershield;"
docker-compose exec postgres psql -U cybershield_user -c "CREATE DATABASE cybershield;"
docker-compose exec postgres psql -U cybershield_user -d cybershield -f /docker-entrypoint-initdb.d/init-db.sql
```

### **Monitor Database:**
```bash
# Check database size
docker-compose exec postgres psql -U cybershield_user -d cybershield -c "SELECT pg_size_pretty(pg_database_size('cybershield'));"

# Check table sizes
docker-compose exec postgres psql -U cybershield_user -d cybershield -c "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"
```

## 📈 Best Practices

1. **Always use parameterized queries** to prevent SQL injection
2. **Use transactions** for multiple related operations
3. **Create indexes** on frequently queried columns
4. **Regular backups** of important data
5. **Monitor database performance** and optimize slow queries
6. **Use appropriate data types** for each column
7. **Implement proper error handling** in application code

## 🚀 Next Steps

1. **Explore the API endpoints** at http://localhost:8000/docs
2. **Create custom data insertion scripts** for your specific needs
3. **Set up automated data collection** from security tools
4. **Implement data validation** and sanitization
5. **Create reporting queries** for security metrics

---

**Database Connection Details:**
- **Host**: localhost
- **Port**: 5432
- **Database**: cybershield
- **Username**: cybershield_user
- **Password**: cybershield_password 