"""
Network Security API Endpoints
Provides REST API for network security management including:
- Firewall rules management
- IDS/IPS alerts and monitoring
- VPN connection management
- Network Access Control (NAC)
- DNS security
- Network segmentation
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import structlog

from app.core.security import get_current_user
from app.services.network_security_service import (
    network_security_service,
    FirewallRule,
    IDSAlert,
    VPNConnection,
    NACPolicy,
    SecurityLevel,
    ThreatType,
    NetworkSegment
)

logger = structlog.get_logger()
router = APIRouter()

# Firewall Management Endpoints
@router.get("/firewall/rules", response_model=List[Dict[str, Any]])
async def get_firewall_rules(current_user = Depends(get_current_user)):
    """Get all firewall rules"""
    try:
        rules = await network_security_service.get_firewall_rules()
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "action": rule.action,
                "protocol": rule.protocol,
                "source_ip": rule.source_ip,
                "source_port": rule.source_port,
                "destination_ip": rule.destination_ip,
                "destination_port": rule.destination_port,
                "direction": rule.direction,
                "priority": rule.priority,
                "enabled": rule.enabled,
                "description": rule.description,
                "created_at": rule.created_at.isoformat(),
                "updated_at": rule.updated_at.isoformat()
            }
            for rule in rules
        ]
    except Exception as e:
        logger.error("Error getting firewall rules", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get firewall rules")

@router.post("/firewall/rules", response_model=Dict[str, Any])
async def create_firewall_rule(
    rule_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Create a new firewall rule"""
    try:
        rule = await network_security_service.add_firewall_rule(rule_data)
        return {
            "id": rule.id,
            "name": rule.name,
            "action": rule.action,
            "protocol": rule.protocol,
            "source_ip": rule.source_ip,
            "source_port": rule.source_port,
            "destination_ip": rule.destination_ip,
            "destination_port": rule.destination_port,
            "direction": rule.direction,
            "priority": rule.priority,
            "enabled": rule.enabled,
            "description": rule.description,
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat()
        }
    except Exception as e:
        logger.error("Error creating firewall rule", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create firewall rule")

@router.put("/firewall/rules/{rule_id}", response_model=Dict[str, Any])
async def update_firewall_rule(
    rule_id: str,
    updates: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Update an existing firewall rule"""
    try:
        rule = await network_security_service.update_firewall_rule(rule_id, updates)
        if not rule:
            raise HTTPException(status_code=404, detail="Firewall rule not found")
        
        return {
            "id": rule.id,
            "name": rule.name,
            "action": rule.action,
            "protocol": rule.protocol,
            "source_ip": rule.source_ip,
            "source_port": rule.source_port,
            "destination_ip": rule.destination_ip,
            "destination_port": rule.destination_port,
            "direction": rule.direction,
            "priority": rule.priority,
            "enabled": rule.enabled,
            "description": rule.description,
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating firewall rule", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update firewall rule")

@router.delete("/firewall/rules/{rule_id}")
async def delete_firewall_rule(
    rule_id: str,
    current_user = Depends(get_current_user)
):
    """Delete a firewall rule"""
    try:
        success = await network_security_service.delete_firewall_rule(rule_id)
        if not success:
            raise HTTPException(status_code=404, detail="Firewall rule not found")
        
        return {"message": "Firewall rule deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting firewall rule", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete firewall rule")

# IDS/IPS Management Endpoints
@router.get("/ids/alerts", response_model=List[Dict[str, Any]])
async def get_ids_alerts(
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    current_user = Depends(get_current_user)
):
    """Get IDS alerts with optional filtering"""
    try:
        alerts = network_security_service.ids_alerts
        
        # Apply filters
        if severity:
            alerts = [a for a in alerts if a.severity.value == severity]
        if threat_type:
            alerts = [a for a in alerts if a.threat_type.value == threat_type]
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        # Limit results
        alerts = alerts[-limit:] if limit > 0 else alerts
        
        return [
            {
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "threat_type": alert.threat_type.value,
                "severity": alert.severity.value,
                "description": alert.description,
                "signature_id": alert.signature_id,
                "action_taken": alert.action_taken,
                "status": alert.status
            }
            for alert in alerts
        ]
    except Exception as e:
        logger.error("Error getting IDS alerts", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get IDS alerts")

@router.put("/ids/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str,
    current_user = Depends(get_current_user)
):
    """Update IDS alert status"""
    try:
        # Find and update alert
        for alert in network_security_service.ids_alerts:
            if alert.id == alert_id:
                alert.status = status
                return {"message": "Alert status updated successfully"}
        
        raise HTTPException(status_code=404, detail="Alert not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating alert status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update alert status")

# VPN Management Endpoints
@router.get("/vpn/connections", response_model=List[Dict[str, Any]])
async def get_vpn_connections(current_user = Depends(get_current_user)):
    """Get all VPN connections"""
    try:
        connections = await network_security_service.get_vpn_connections()
        return [
            {
                "id": conn.id,
                "user_id": conn.user_id,
                "username": conn.username,
                "ip_address": conn.ip_address,
                "connected_at": conn.connected_at.isoformat(),
                "last_activity": conn.last_activity.isoformat(),
                "bytes_sent": conn.bytes_sent,
                "bytes_received": conn.bytes_received,
                "status": conn.status,
                "client_info": conn.client_info
            }
            for conn in connections
        ]
    except Exception as e:
        logger.error("Error getting VPN connections", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get VPN connections")

@router.post("/vpn/connect")
async def connect_vpn_user(
    connection_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Connect a user to VPN"""
    try:
        connection = await network_security_service.connect_vpn_user(
            user_id=connection_data["user_id"],
            username=connection_data["username"],
            ip_address=connection_data["ip_address"],
            client_info=connection_data.get("client_info", {})
        )
        
        return {
            "id": connection.id,
            "user_id": connection.user_id,
            "username": connection.username,
            "ip_address": connection.ip_address,
            "connected_at": connection.connected_at.isoformat(),
            "status": connection.status
        }
    except Exception as e:
        logger.error("Error connecting VPN user", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to connect VPN user")

@router.post("/vpn/disconnect/{connection_id}")
async def disconnect_vpn_user(
    connection_id: str,
    current_user = Depends(get_current_user)
):
    """Disconnect a VPN user"""
    try:
        success = await network_security_service.disconnect_vpn_user(connection_id)
        if not success:
            raise HTTPException(status_code=404, detail="VPN connection not found")
        
        return {"message": "VPN user disconnected successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error disconnecting VPN user", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to disconnect VPN user")

# NAC Management Endpoints
@router.get("/nac/policies", response_model=List[Dict[str, Any]])
async def get_nac_policies(current_user = Depends(get_current_user)):
    """Get all NAC policies"""
    try:
        policies = list(network_security_service.nac_policies.values())
        return [
            {
                "id": policy.id,
                "name": policy.name,
                "description": policy.description,
                "device_requirements": policy.device_requirements,
                "network_access": policy.network_access,
                "time_restrictions": policy.time_restrictions,
                "enabled": policy.enabled,
                "priority": policy.priority
            }
            for policy in policies
        ]
    except Exception as e:
        logger.error("Error getting NAC policies", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get NAC policies")

@router.post("/nac/policies", response_model=Dict[str, Any])
async def create_nac_policy(
    policy_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Create a new NAC policy"""
    try:
        policy = await network_security_service.add_nac_policy(policy_data)
        return {
            "id": policy.id,
            "name": policy.name,
            "description": policy.description,
            "device_requirements": policy.device_requirements,
            "network_access": policy.network_access,
            "time_restrictions": policy.time_restrictions,
            "enabled": policy.enabled,
            "priority": policy.priority
        }
    except Exception as e:
        logger.error("Error creating NAC policy", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create NAC policy")

@router.post("/nac/evaluate")
async def evaluate_device_access(
    device_info: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Evaluate device access based on NAC policies"""
    try:
        result = await network_security_service.evaluate_device_access(
            device_info=device_info,
            user_id=str(current_user.id)
        )
        return result
    except Exception as e:
        logger.error("Error evaluating device access", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to evaluate device access")

# DNS Security Endpoints
@router.post("/dns/check")
async def check_dns_request(
    domain: str,
    current_user = Depends(get_current_user)
):
    """Check if DNS request should be allowed"""
    try:
        result = await network_security_service.check_dns_request(domain)
        return result
    except Exception as e:
        logger.error("Error checking DNS request", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to check DNS request")

@router.post("/dns/blacklist")
async def add_dns_blacklist(
    domain: str,
    current_user = Depends(get_current_user)
):
    """Add domain to DNS blacklist"""
    try:
        success = await network_security_service.add_dns_blacklist(domain)
        return {"message": "Domain added to blacklist successfully"}
    except Exception as e:
        logger.error("Error adding domain to blacklist", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to add domain to blacklist")

@router.post("/dns/whitelist")
async def add_dns_whitelist(
    domain: str,
    current_user = Depends(get_current_user)
):
    """Add domain to DNS whitelist"""
    try:
        success = await network_security_service.add_dns_whitelist(domain)
        return {"message": "Domain added to whitelist successfully"}
    except Exception as e:
        logger.error("Error adding domain to whitelist", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to add domain to whitelist")

@router.get("/dns/blacklist")
async def get_dns_blacklist(current_user = Depends(get_current_user)):
    """Get DNS blacklist"""
    try:
        return {
            "domains": list(network_security_service.dns_blacklist),
            "count": len(network_security_service.dns_blacklist)
        }
    except Exception as e:
        logger.error("Error getting DNS blacklist", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DNS blacklist")

@router.get("/dns/whitelist")
async def get_dns_whitelist(current_user = Depends(get_current_user)):
    """Get DNS whitelist"""
    try:
        return {
            "domains": list(network_security_service.dns_whitelist),
            "count": len(network_security_service.dns_whitelist)
        }
    except Exception as e:
        logger.error("Error getting DNS whitelist", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DNS whitelist")

# Network Segmentation Endpoints
@router.get("/segments", response_model=Dict[str, Any])
async def get_network_segments(current_user = Depends(get_current_user)):
    """Get all network segments"""
    try:
        segments = await network_security_service.get_network_segments()
        return segments
    except Exception as e:
        logger.error("Error getting network segments", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get network segments")

@router.post("/segments", response_model=Dict[str, Any])
async def create_network_segment(
    segment_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Create a new network segment"""
    try:
        segment = await network_security_service.create_network_segment(segment_data)
        return segment
    except Exception as e:
        logger.error("Error creating network segment", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create network segment")

# Reporting Endpoints
@router.get("/reports/security")
async def get_security_report(current_user = Depends(get_current_user)):
    """Get comprehensive security report"""
    try:
        report = await network_security_service.get_security_report()
        return report
    except Exception as e:
        logger.error("Error generating security report", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate security report")

@router.get("/status")
async def get_network_status(current_user = Depends(get_current_user)):
    """Get current network security status"""
    try:
        status = await network_security_service.get_network_status()
        return status
    except Exception as e:
        logger.error("Error getting network status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get network status")

# Threat Intelligence Endpoints
@router.get("/threats/blocked-ips")
async def get_blocked_ips(current_user = Depends(get_current_user)):
    """Get list of blocked IP addresses"""
    try:
        return {
            "blocked_ips": list(network_security_service.blocked_ips),
            "count": len(network_security_service.blocked_ips)
        }
    except Exception as e:
        logger.error("Error getting blocked IPs", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get blocked IPs")

@router.post("/threats/block-ip")
async def block_ip(
    ip_address: str,
    reason: str = "Manual block",
    current_user = Depends(get_current_user)
):
    """Manually block an IP address"""
    try:
        network_security_service.blocked_ips.add(ip_address)
        logger.info("IP manually blocked", ip_address=ip_address, reason=reason, user_id=current_user.id)
        return {"message": f"IP {ip_address} blocked successfully"}
    except Exception as e:
        logger.error("Error blocking IP", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to block IP")

@router.delete("/threats/unblock-ip/{ip_address}")
async def unblock_ip(
    ip_address: str,
    current_user = Depends(get_current_user)
):
    """Unblock an IP address"""
    try:
        if ip_address in network_security_service.blocked_ips:
            network_security_service.blocked_ips.remove(ip_address)
            logger.info("IP manually unblocked", ip_address=ip_address, user_id=current_user.id)
            return {"message": f"IP {ip_address} unblocked successfully"}
        else:
            raise HTTPException(status_code=404, detail="IP not found in blocked list")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error unblocking IP", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to unblock IP")

# DDoS Protection Endpoints
@router.get("/ddos/attacks")
async def get_ddos_attacks(
    hours: int = 24,
    current_user = Depends(get_current_user)
):
    """Get DDoS attacks from the last N hours"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_attacks = [
            attack for attack in network_security_service.ddos_attacks
            if attack["timestamp"] > cutoff_time
        ]
        
        return {
            "attacks": recent_attacks,
            "count": len(recent_attacks),
            "time_period_hours": hours
        }
    except Exception as e:
        logger.error("Error getting DDoS attacks", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DDoS attacks")

# Network Monitoring Endpoints
@router.get("/monitoring/traffic")
async def get_traffic_analysis(current_user = Depends(get_current_user)):
    """Get network traffic analysis"""
    try:
        # Simulate traffic analysis data
        traffic_data = {
            "total_connections": 1250,
            "active_connections": 89,
            "bandwidth_usage": {
                "inbound": "45.2 Mbps",
                "outbound": "23.1 Mbps"
            },
            "top_protocols": [
                {"protocol": "HTTP", "percentage": 45},
                {"protocol": "HTTPS", "percentage": 35},
                {"protocol": "SSH", "percentage": 10},
                {"protocol": "DNS", "percentage": 5},
                {"protocol": "Other", "percentage": 5}
            ],
            "top_source_ips": [
                {"ip": "192.168.1.100", "connections": 156},
                {"ip": "10.0.2.15", "connections": 89},
                {"ip": "172.16.0.25", "connections": 67}
            ],
            "top_destination_ips": [
                {"ip": "8.8.8.8", "connections": 234},
                {"ip": "1.1.1.1", "connections": 189},
                {"ip": "208.67.222.222", "connections": 145}
            ]
        }
        
        return traffic_data
    except Exception as e:
        logger.error("Error getting traffic analysis", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get traffic analysis")

@router.get("/monitoring/ports")
async def get_port_analysis(current_user = Depends(get_current_user)):
    """Get port usage analysis"""
    try:
        # Simulate port analysis data
        port_data = {
            "most_accessed_ports": [
                {"port": 80, "connections": 456, "service": "HTTP"},
                {"port": 443, "connections": 389, "service": "HTTPS"},
                {"port": 22, "connections": 234, "service": "SSH"},
                {"port": 53, "connections": 178, "service": "DNS"},
                {"port": 3389, "connections": 67, "service": "RDP"}
            ],
            "suspicious_ports": [
                {"port": 23, "connections": 12, "service": "Telnet", "risk": "High"},
                {"port": 21, "connections": 8, "service": "FTP", "risk": "Medium"},
                {"port": 1433, "connections": 5, "service": "SQL Server", "risk": "Medium"}
            ],
            "port_scan_attempts": 23,
            "last_scan_detected": "2024-01-15T14:30:00Z"
        }
        
        return port_data
    except Exception as e:
        logger.error("Error getting port analysis", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get port analysis") 