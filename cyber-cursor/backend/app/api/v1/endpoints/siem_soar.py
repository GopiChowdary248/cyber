from fastapi import APIRouter, HTTPException, Depends, status
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import random

router = APIRouter()

# Mock data for SIEM & SOAR
MOCK_SIEM_DATA = {
    "overview": {
        "total_logs": 15420000,
        "active_alerts": 23,
        "open_incidents": 8,
        "security_score": 94
    },
    "log_collection": {
        "total_sources": 156,
        "logs_per_second": 2450,
        "storage_used": 2.4,
        "status": "healthy"
    },
    "event_correlation": {
        "correlation_rules": 89,
        "active_rules": 85,
        "events_correlated": 45670,
        "status": "healthy"
    },
    "incident_management": {
        "total_incidents": 234,
        "open_incidents": 8,
        "resolved_today": 12,
        "avg_resolution_time": 2.5
    },
    "playbooks": {
        "total_playbooks": 45,
        "active_playbooks": 42,
        "executions_today": 156,
        "success_rate": 98.5
    },
    "threat_intelligence": {
        "total_feeds": 23,
        "active_feeds": 21,
        "iocs_processed": 12340,
        "last_update": "2 minutes ago"
    },
    "automation": {
        "total_actions": 890,
        "successful_actions": 875,
        "failed_actions": 15,
        "avg_response_time": 0.8
    },
    "compliance": {
        "total_reports": 89,
        "compliance_score": 96,
        "audit_logs": 45670,
        "last_audit": "1 hour ago"
    }
}

MOCK_INCIDENTS = [
    {
        "id": "INC-001",
        "title": "Suspicious Login Attempts",
        "severity": "high",
        "status": "open",
        "assigned_to": "analyst1@company.com",
        "created_at": "2025-08-02T10:30:00Z",
        "description": "Multiple failed login attempts detected from suspicious IP addresses",
        "source": "Firewall Logs",
        "playbook_executed": "IP Blocking Playbook"
    },
    {
        "id": "INC-002",
        "title": "Data Exfiltration Attempt",
        "severity": "critical",
        "status": "investigating",
        "assigned_to": "analyst2@company.com",
        "created_at": "2025-08-02T09:15:00Z",
        "description": "Large data transfer detected to external IP address",
        "source": "DLP System",
        "playbook_executed": "Host Isolation Playbook"
    },
    {
        "id": "INC-003",
        "title": "Malware Detection",
        "severity": "medium",
        "status": "resolved",
        "assigned_to": "analyst3@company.com",
        "created_at": "2025-08-02T08:45:00Z",
        "description": "Malware detected on endpoint device",
        "source": "EDR System",
        "playbook_executed": "Endpoint Quarantine Playbook"
    }
]

MOCK_PLAYBOOKS = [
    {
        "id": "PB-001",
        "name": "IP Blocking Playbook",
        "description": "Automatically block suspicious IP addresses",
        "status": "active",
        "executions_today": 45,
        "success_rate": 98.5,
        "triggers": ["Failed Login", "Brute Force Attack"],
        "actions": ["Block IP on Firewall", "Add to Blacklist", "Send Alert"]
    },
    {
        "id": "PB-002",
        "name": "Host Isolation Playbook",
        "description": "Isolate compromised hosts from network",
        "status": "active",
        "executions_today": 12,
        "success_rate": 95.2,
        "triggers": ["Malware Detection", "Data Exfiltration"],
        "actions": ["Disconnect from Network", "Quarantine Device", "Notify Admin"]
    },
    {
        "id": "PB-003",
        "name": "Account Disable Playbook",
        "description": "Disable compromised user accounts",
        "status": "active",
        "executions_today": 8,
        "success_rate": 100.0,
        "triggers": ["Account Compromise", "Suspicious Activity"],
        "actions": ["Disable Account", "Force Password Reset", "Log Activity"]
    }
]

MOCK_THREAT_FEEDS = [
    {
        "id": "TF-001",
        "name": "VirusTotal",
        "status": "active",
        "last_update": "2025-08-02T18:45:00Z",
        "iocs_processed": 3450,
        "api_status": "healthy"
    },
    {
        "id": "TF-002",
        "name": "AbuseIPDB",
        "status": "active",
        "last_update": "2025-08-02T18:42:00Z",
        "iocs_processed": 2890,
        "api_status": "healthy"
    },
    {
        "id": "TF-003",
        "name": "AlienVault OTX",
        "status": "active",
        "last_update": "2025-08-02T18:40:00Z",
        "iocs_processed": 4120,
        "api_status": "healthy"
    }
]

@router.get("/overview")
async def get_siem_overview():
    """Get SIEM & SOAR overview data"""
    return {
        "status": "success",
        "data": MOCK_SIEM_DATA["overview"],
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/log-collection")
async def get_log_collection_status():
    """Get log collection status and metrics"""
    return {
        "status": "success",
        "data": MOCK_SIEM_DATA["log_collection"],
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/event-correlation")
async def get_event_correlation_status():
    """Get event correlation engine status"""
    return {
        "status": "success",
        "data": MOCK_SIEM_DATA["event_correlation"],
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/incidents")
async def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 10
):
    """Get incidents with optional filtering"""
    incidents = MOCK_INCIDENTS.copy()
    
    if status:
        incidents = [inc for inc in incidents if inc["status"] == status]
    
    if severity:
        incidents = [inc for inc in incidents if inc["severity"] == severity]
    
    return {
        "status": "success",
        "data": {
            "incidents": incidents[:limit],
            "summary": MOCK_SIEM_DATA["incident_management"]
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get specific incident details"""
    incident = next((inc for inc in MOCK_INCIDENTS if inc["id"] == incident_id), None)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "status": "success",
        "data": incident,
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/incidents/{incident_id}/update")
async def update_incident(incident_id: str, update_data: Dict[str, Any]):
    """Update incident status or details"""
    incident = next((inc for inc in MOCK_INCIDENTS if inc["id"] == incident_id), None)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Simulate update
    incident.update(update_data)
    
    return {
        "status": "success",
        "message": "Incident updated successfully",
        "data": incident,
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/playbooks")
async def get_playbooks():
    """Get all playbooks"""
    return {
        "status": "success",
        "data": {
            "playbooks": MOCK_PLAYBOOKS,
            "summary": MOCK_SIEM_DATA["playbooks"]
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str):
    """Get specific playbook details"""
    playbook = next((pb for pb in MOCK_PLAYBOOKS if pb["id"] == playbook_id), None)
    
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    return {
        "status": "success",
        "data": playbook,
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, execution_data: Dict[str, Any]):
    """Execute a playbook"""
    playbook = next((pb for pb in MOCK_PLAYBOOKS if pb["id"] == playbook_id), None)
    
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # Simulate execution
    execution_id = f"EXEC-{random.randint(1000, 9999)}"
    
    return {
        "status": "success",
        "message": "Playbook executed successfully",
        "data": {
            "execution_id": execution_id,
            "playbook_name": playbook["name"],
            "status": "completed",
            "execution_time": random.uniform(0.5, 2.0),
            "actions_executed": len(playbook["actions"])
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/threat-intelligence")
async def get_threat_intelligence():
    """Get threat intelligence feeds and data"""
    return {
        "status": "success",
        "data": {
            "feeds": MOCK_THREAT_FEEDS,
            "summary": MOCK_SIEM_DATA["threat_intelligence"]
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/threat-intelligence/lookup")
async def lookup_ioc(ioc_data: Dict[str, str]):
    """Lookup IOC in threat intelligence feeds"""
    ioc_value = ioc_data.get("value", "")
    ioc_type = ioc_data.get("type", "ip")
    
    # Simulate IOC lookup
    threat_score = random.randint(0, 100)
    is_malicious = threat_score > 70
    
    return {
        "status": "success",
        "data": {
            "ioc": ioc_value,
            "type": ioc_type,
            "threat_score": threat_score,
            "is_malicious": is_malicious,
            "sources": random.randint(3, 8),
            "first_seen": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "tags": ["malware", "phishing"] if is_malicious else []
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/automation")
async def get_automation_status():
    """Get automation status and metrics"""
    return {
        "status": "success",
        "data": MOCK_SIEM_DATA["automation"],
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/automation/actions")
async def execute_automated_action(action_data: Dict[str, Any]):
    """Execute automated security action"""
    action_type = action_data.get("type", "")
    target = action_data.get("target", "")
    
    # Simulate action execution
    success = random.random() > 0.1  # 90% success rate
    
    return {
        "status": "success" if success else "failed",
        "message": f"Action {action_type} executed successfully" if success else f"Action {action_type} failed",
        "data": {
            "action_id": f"ACT-{random.randint(1000, 9999)}",
            "action_type": action_type,
            "target": target,
            "status": "completed" if success else "failed",
            "execution_time": random.uniform(0.1, 1.0),
            "timestamp": datetime.utcnow().isoformat()
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/compliance")
async def get_compliance_status():
    """Get compliance status and reports"""
    return {
        "status": "success",
        "data": MOCK_SIEM_DATA["compliance"],
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/compliance/reports/generate")
async def generate_compliance_report(report_data: Dict[str, Any]):
    """Generate compliance report"""
    report_type = report_data.get("type", "general")
    date_range = report_data.get("date_range", "last_30_days")
    
    # Simulate report generation
    report_id = f"REP-{random.randint(1000, 9999)}"
    
    return {
        "status": "success",
        "message": "Compliance report generated successfully",
        "data": {
            "report_id": report_id,
            "report_type": report_type,
            "date_range": date_range,
            "status": "completed",
            "download_url": f"/api/v1/siem-soar/reports/{report_id}/download",
            "generated_at": datetime.utcnow().isoformat()
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/logs/search")
async def search_logs(
    query: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100
):
    """Search logs with various filters"""
    # Simulate log search
    mock_logs = []
    for i in range(min(limit, 50)):
        mock_logs.append({
            "id": f"LOG-{random.randint(10000, 99999)}",
            "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            "source": random.choice(["firewall", "server", "application", "database"]),
            "level": random.choice(["info", "warning", "error", "critical"]),
            "message": f"Log entry {i+1} matching query: {query}",
            "details": {
                "ip_address": f"192.168.1.{random.randint(1, 254)}",
                "user": f"user{random.randint(1, 100)}",
                "action": random.choice(["login", "logout", "access", "modify"])
            }
        })
    
    return {
        "status": "success",
        "data": {
            "logs": mock_logs,
            "total_count": len(mock_logs),
            "query": query,
            "search_time": random.uniform(0.1, 2.0)
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/alerts")
async def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20
):
    """Get security alerts"""
    # Simulate alerts
    mock_alerts = []
    for i in range(min(limit, 20)):
        mock_alerts.append({
            "id": f"ALT-{random.randint(1000, 9999)}",
            "title": f"Security Alert {i+1}",
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "status": random.choice(["new", "acknowledged", "investigating", "resolved"]),
            "source": random.choice(["correlation_engine", "threat_intel", "manual"]),
            "created_at": (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat(),
            "description": f"Security alert description {i+1}",
            "affected_assets": random.randint(1, 5)
        })
    
    if status:
        mock_alerts = [alert for alert in mock_alerts if alert["status"] == status]
    
    if severity:
        mock_alerts = [alert for alert in mock_alerts if alert["severity"] == severity]
    
    return {
        "status": "success",
        "data": {
            "alerts": mock_alerts,
            "total_count": len(mock_alerts),
            "summary": {
                "total_alerts": MOCK_SIEM_DATA["overview"]["active_alerts"],
                "critical_alerts": len([a for a in mock_alerts if a["severity"] == "critical"]),
                "high_alerts": len([a for a in mock_alerts if a["severity"] == "high"])
            }
        },
        "timestamp": datetime.utcnow().isoformat()
    } 