"""
Network Security Service
Implements comprehensive network security technologies including:
- Firewall management
- IDS/IPS monitoring
- VPN management
- Network Access Control (NAC)
- DNS security
- DDoS protection
- Port security
- Network segmentation
"""

import asyncio
import structlog
import ipaddress
import subprocess
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
import socket
import threading
import queue

logger = structlog.get_logger()

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"

class NetworkSegment(Enum):
    DMZ = "dmz"
    INTERNAL = "internal"
    GUEST = "guest"
    FINANCE = "finance"
    DEVELOPMENT = "development"
    ADMIN = "admin"
    IoT = "iot"

@dataclass
class FirewallRule:
    id: str
    name: str
    action: str  # allow, deny, drop
    protocol: str  # tcp, udp, icmp, any
    source_ip: str
    source_port: Optional[str]
    destination_ip: str
    destination_port: Optional[str]
    direction: str  # inbound, outbound, both
    priority: int
    enabled: bool
    description: str
    created_at: datetime
    updated_at: datetime

@dataclass
class IDSAlert:
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    threat_type: ThreatType
    severity: SecurityLevel
    description: str
    signature_id: str
    packet_data: Optional[str]
    action_taken: str
    status: str  # new, investigating, resolved, false_positive

@dataclass
class VPNConnection:
    id: str
    user_id: str
    username: str
    ip_address: str
    connected_at: datetime
    last_activity: datetime
    bytes_sent: int
    bytes_received: int
    status: str  # connected, disconnected, idle
    client_info: Dict[str, Any]

@dataclass
class NACPolicy:
    id: str
    name: str
    description: str
    device_requirements: Dict[str, Any]
    network_access: List[str]
    time_restrictions: Dict[str, Any]
    enabled: bool
    priority: int

class NetworkSecurityService:
    def __init__(self):
        self.firewall_rules: Dict[str, FirewallRule] = {}
        self.ids_alerts: List[IDSAlert] = []
        self.vpn_connections: Dict[str, VPNConnection] = {}
        self.nac_policies: Dict[str, NACPolicy] = {}
        self.blocked_ips: set = set()
        self.suspicious_ips: Dict[str, Dict[str, Any]] = {}
        self.dns_blacklist: set = set()
        self.dns_whitelist: set = set()
        self.network_segments: Dict[str, Dict[str, Any]] = {}
        self.ddos_attacks: List[Dict[str, Any]] = []
        self.security_events: queue.Queue = queue.Queue()
        
        # Initialize default configurations
        self._initialize_default_config()
        
        # Start background tasks
        asyncio.create_task(self._start_network_monitoring())
        asyncio.create_task(self._start_threat_detection())
        asyncio.create_task(self._start_ddos_protection())
        asyncio.create_task(self._start_dns_monitoring())
        
    def _initialize_default_config(self):
        """Initialize default network security configurations"""
        logger.info("Initializing network security configurations")
        
        # Initialize network segments
        self.network_segments = {
            NetworkSegment.DMZ.value: {
                "subnet": "10.0.1.0/24",
                "description": "Demilitarized Zone",
                "security_level": SecurityLevel.HIGH.value,
                "allowed_services": ["http", "https", "ssh"],
                "monitoring": True
            },
            NetworkSegment.INTERNAL.value: {
                "subnet": "10.0.2.0/24",
                "description": "Internal Network",
                "security_level": SecurityLevel.MEDIUM.value,
                "allowed_services": ["ssh", "rdp", "vnc"],
                "monitoring": True
            },
            NetworkSegment.GUEST.value: {
                "subnet": "10.0.3.0/24",
                "description": "Guest Network",
                "security_level": SecurityLevel.LOW.value,
                "allowed_services": ["http", "https"],
                "monitoring": True
            },
            NetworkSegment.FINANCE.value: {
                "subnet": "10.0.4.0/24",
                "description": "Finance Department",
                "security_level": SecurityLevel.CRITICAL.value,
                "allowed_services": ["ssh", "database"],
                "monitoring": True
            },
            NetworkSegment.DEVELOPMENT.value: {
                "subnet": "10.0.5.0/24",
                "description": "Development Environment",
                "security_level": SecurityLevel.MEDIUM.value,
                "allowed_services": ["ssh", "http", "https", "database"],
                "monitoring": True
            }
        }
        
        # Initialize default firewall rules
        self._create_default_firewall_rules()
        
        # Initialize NAC policies
        self._create_default_nac_policies()
        
        # Initialize DNS blacklist
        self._load_dns_blacklist()
        
    def _create_default_firewall_rules(self):
        """Create default firewall rules"""
        default_rules = [
            {
                "id": "default_deny_all",
                "name": "Default Deny All",
                "action": "deny",
                "protocol": "any",
                "source_ip": "0.0.0.0/0",
                "source_port": None,
                "destination_ip": "0.0.0.0/0",
                "destination_port": None,
                "direction": "both",
                "priority": 1000,
                "enabled": True,
                "description": "Default deny rule for all traffic"
            },
            {
                "id": "allow_http_https",
                "name": "Allow HTTP/HTTPS",
                "action": "allow",
                "protocol": "tcp",
                "source_ip": "0.0.0.0/0",
                "source_port": None,
                "destination_ip": "10.0.1.0/24",
                "destination_port": "80,443",
                "direction": "inbound",
                "priority": 100,
                "enabled": True,
                "description": "Allow HTTP and HTTPS traffic to DMZ"
            },
            {
                "id": "allow_ssh_internal",
                "name": "Allow SSH Internal",
                "action": "allow",
                "protocol": "tcp",
                "source_ip": "10.0.0.0/8",
                "source_port": None,
                "destination_ip": "10.0.0.0/8",
                "destination_port": "22",
                "direction": "both",
                "priority": 200,
                "enabled": True,
                "description": "Allow SSH between internal networks"
            }
        ]
        
        for rule_data in default_rules:
            rule = FirewallRule(
                id=rule_data["id"],
                name=rule_data["name"],
                action=rule_data["action"],
                protocol=rule_data["protocol"],
                source_ip=rule_data["source_ip"],
                source_port=rule_data["source_port"],
                destination_ip=rule_data["destination_ip"],
                destination_port=rule_data["destination_port"],
                direction=rule_data["direction"],
                priority=rule_data["priority"],
                enabled=rule_data["enabled"],
                description=rule_data["description"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            self.firewall_rules[rule.id] = rule
            
    def _create_default_nac_policies(self):
        """Create default NAC policies"""
        default_policies = [
            {
                "id": "default_employee",
                "name": "Default Employee Access",
                "description": "Standard access for employees",
                "device_requirements": {
                    "antivirus_installed": True,
                    "os_updates": True,
                    "firewall_enabled": True
                },
                "network_access": [NetworkSegment.INTERNAL.value],
                "time_restrictions": {
                    "business_hours": True,
                    "start_time": "08:00",
                    "end_time": "18:00"
                },
                "enabled": True,
                "priority": 100
            },
            {
                "id": "admin_access",
                "name": "Administrator Access",
                "description": "Full network access for administrators",
                "device_requirements": {
                    "antivirus_installed": True,
                    "os_updates": True,
                    "firewall_enabled": True,
                    "mfa_enabled": True
                },
                "network_access": [NetworkSegment.ADMIN.value, NetworkSegment.INTERNAL.value],
                "time_restrictions": {
                    "business_hours": False,
                    "start_time": "00:00",
                    "end_time": "23:59"
                },
                "enabled": True,
                "priority": 50
            }
        ]
        
        for policy_data in default_policies:
            policy = NACPolicy(
                id=policy_data["id"],
                name=policy_data["name"],
                description=policy_data["description"],
                device_requirements=policy_data["device_requirements"],
                network_access=policy_data["network_access"],
                time_restrictions=policy_data["time_restrictions"],
                enabled=policy_data["enabled"],
                priority=policy_data["priority"]
            )
            self.nac_policies[policy.id] = policy
            
    def _load_dns_blacklist(self):
        """Load DNS blacklist from common malware domains"""
        # Common malware and phishing domains
        blacklist_domains = [
            "malware.example.com",
            "phishing.example.com",
            "botnet.example.com",
            "c2.example.com",
            "malicious.example.com"
        ]
        
        for domain in blacklist_domains:
            self.dns_blacklist.add(domain)
            
    async def start_network_security_service(self):
        """Start the network security service"""
        logger.info("Starting network security service")
        
        # Start background monitoring tasks
        asyncio.create_task(self._monitor_network_traffic())
        asyncio.create_task(self._monitor_vpn_connections())
        asyncio.create_task(self._cleanup_old_alerts())
        
        logger.info("Network security service started successfully")
        
    async def _monitor_network_traffic(self):
        """Monitor network traffic for suspicious activity"""
        while True:
            try:
                # Simulate network traffic monitoring
                await self._analyze_network_traffic()
                await asyncio.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error("Error monitoring network traffic", error=str(e))
                await asyncio.sleep(60)
                
    async def _analyze_network_traffic(self):
        """Analyze network traffic for threats"""
        # Simulate traffic analysis
        # In a real implementation, this would analyze actual network packets
        
        # Check for port scanning
        await self._detect_port_scanning()
        
        # Check for DDoS attacks
        await self._detect_ddos_attacks()
        
        # Check for suspicious connections
        await self._detect_suspicious_connections()
        
    async def _detect_port_scanning(self):
        """Detect port scanning activities"""
        # Simulate port scan detection
        # In real implementation, this would analyze connection patterns
        
        suspicious_patterns = [
            {"source_ip": "192.168.1.100", "ports": [22, 23, 25, 80, 443, 3389]},
            {"source_ip": "10.0.0.50", "ports": [21, 22, 23, 25, 53, 80]}
        ]
        
        for pattern in suspicious_patterns:
            if self._is_port_scanning(pattern):
                await self._create_ids_alert(
                    source_ip=pattern["source_ip"],
                    threat_type=ThreatType.PORT_SCAN,
                    severity=SecurityLevel.HIGH,
                    description=f"Port scanning detected from {pattern['source_ip']}"
                )
                
    def _is_port_scanning(self, pattern: Dict[str, Any]) -> bool:
        """Check if traffic pattern indicates port scanning"""
        # Simple heuristic: if more than 5 ports are accessed in short time
        return len(pattern["ports"]) > 5
        
    async def _detect_ddos_attacks(self):
        """Detect DDoS attacks"""
        # Simulate DDoS detection
        # In real implementation, this would analyze traffic volume and patterns
        
        high_traffic_sources = [
            {"ip": "203.0.113.1", "requests_per_second": 1000},
            {"ip": "198.51.100.5", "requests_per_second": 800}
        ]
        
        for source in high_traffic_sources:
            if source["requests_per_second"] > 500:
                await self._handle_ddos_attack(source["ip"])
                
    async def _handle_ddos_attack(self, source_ip: str):
        """Handle DDoS attack by blocking source IP"""
        self.blocked_ips.add(source_ip)
        
        attack_info = {
            "source_ip": source_ip,
            "timestamp": datetime.utcnow(),
            "type": "DDoS",
            "severity": SecurityLevel.CRITICAL.value,
            "action_taken": "IP blocked"
        }
        
        self.ddos_attacks.append(attack_info)
        
        await self._create_ids_alert(
            source_ip=source_ip,
            threat_type=ThreatType.DDoS,
            severity=SecurityLevel.CRITICAL,
            description=f"DDoS attack detected from {source_ip}"
        )
        
        logger.warning("DDoS attack detected and blocked", source_ip=source_ip)
        
    async def _detect_suspicious_connections(self):
        """Detect suspicious network connections"""
        # Simulate suspicious connection detection
        suspicious_connections = [
            {"source_ip": "10.0.2.15", "destination_ip": "8.8.8.8", "port": 53},
            {"source_ip": "10.0.3.20", "destination_ip": "1.1.1.1", "port": 443}
        ]
        
        for conn in suspicious_connections:
            if self._is_suspicious_connection(conn):
                await self._create_ids_alert(
                    source_ip=conn["source_ip"],
                    threat_type=ThreatType.SUSPICIOUS_TRAFFIC,
                    severity=SecurityLevel.MEDIUM,
                    description=f"Suspicious connection to {conn['destination_ip']}:{conn['port']}"
                )
                
    def _is_suspicious_connection(self, connection: Dict[str, Any]) -> bool:
        """Check if connection is suspicious"""
        # Simple heuristic: external connections from internal networks
        internal_networks = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
        
        source_ip = ipaddress.ip_address(connection["source_ip"])
        dest_ip = ipaddress.ip_address(connection["destination_ip"])
        
        # Check if source is internal and destination is external
        source_internal = any(source_ip in ipaddress.ip_network(net) for net in internal_networks)
        dest_external = not any(dest_ip in ipaddress.ip_network(net) for net in internal_networks)
        
        return source_internal and dest_external
        
    async def _create_ids_alert(self, source_ip: str, threat_type: ThreatType, 
                               severity: SecurityLevel, description: str):
        """Create an IDS alert"""
        alert = IDSAlert(
            id=f"alert_{int(time.time())}",
            timestamp=datetime.utcnow(),
            source_ip=source_ip,
            destination_ip="",
            threat_type=threat_type,
            severity=severity,
            description=description,
            signature_id=f"sig_{threat_type.value}",
            packet_data=None,
            action_taken="logged",
            status="new"
        )
        
        self.ids_alerts.append(alert)
        
        # Add to security events queue
        self.security_events.put({
            "type": "ids_alert",
            "alert": alert,
            "timestamp": datetime.utcnow()
        })
        
        logger.warning("IDS alert created", 
                      threat_type=threat_type.value,
                      severity=severity.value,
                      source_ip=source_ip)
        
    async def _monitor_vpn_connections(self):
        """Monitor VPN connections"""
        while True:
            try:
                # Check for idle connections
                current_time = datetime.utcnow()
                idle_connections = []
                
                for conn_id, connection in self.vpn_connections.items():
                    if connection.status == "connected":
                        idle_time = current_time - connection.last_activity
                        if idle_time > timedelta(hours=8):  # 8 hours idle
                            idle_connections.append(conn_id)
                            
                # Disconnect idle connections
                for conn_id in idle_connections:
                    await self.disconnect_vpn_user(conn_id)
                    
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error("Error monitoring VPN connections", error=str(e))
                await asyncio.sleep(600)
                
    async def _cleanup_old_alerts(self):
        """Clean up old IDS alerts"""
        while True:
            try:
                current_time = datetime.utcnow()
                cutoff_time = current_time - timedelta(days=30)
                
                # Remove alerts older than 30 days
                self.ids_alerts = [
                    alert for alert in self.ids_alerts 
                    if alert.timestamp > cutoff_time
                ]
                
                await asyncio.sleep(3600)  # Clean up every hour
                
            except Exception as e:
                logger.error("Error cleaning up old alerts", error=str(e))
                await asyncio.sleep(3600)
                
    # Firewall Management Methods
    async def add_firewall_rule(self, rule_data: Dict[str, Any]) -> FirewallRule:
        """Add a new firewall rule"""
        rule = FirewallRule(
            id=rule_data["id"],
            name=rule_data["name"],
            action=rule_data["action"],
            protocol=rule_data["protocol"],
            source_ip=rule_data["source_ip"],
            source_port=rule_data.get("source_port"),
            destination_ip=rule_data["destination_ip"],
            destination_port=rule_data.get("destination_port"),
            direction=rule_data["direction"],
            priority=rule_data["priority"],
            enabled=rule_data["enabled"],
            description=rule_data["description"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        self.firewall_rules[rule.id] = rule
        logger.info("Firewall rule added", rule_id=rule.id, rule_name=rule.name)
        
        return rule
        
    async def update_firewall_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[FirewallRule]:
        """Update an existing firewall rule"""
        if rule_id not in self.firewall_rules:
            return None
            
        rule = self.firewall_rules[rule_id]
        
        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
                
        rule.updated_at = datetime.utcnow()
        
        logger.info("Firewall rule updated", rule_id=rule_id)
        return rule
        
    async def delete_firewall_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule"""
        if rule_id in self.firewall_rules:
            del self.firewall_rules[rule_id]
            logger.info("Firewall rule deleted", rule_id=rule_id)
            return True
        return False
        
    async def get_firewall_rules(self) -> List[FirewallRule]:
        """Get all firewall rules"""
        return list(self.firewall_rules.values())
        
    # VPN Management Methods
    async def connect_vpn_user(self, user_id: str, username: str, ip_address: str, 
                              client_info: Dict[str, Any]) -> VPNConnection:
        """Connect a user to VPN"""
        connection = VPNConnection(
            id=f"vpn_{user_id}_{int(time.time())}",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            connected_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            bytes_sent=0,
            bytes_received=0,
            status="connected",
            client_info=client_info
        )
        
        self.vpn_connections[connection.id] = connection
        
        logger.info("VPN user connected", 
                   user_id=user_id, 
                   username=username, 
                   ip_address=ip_address)
        
        return connection
        
    async def disconnect_vpn_user(self, connection_id: str) -> bool:
        """Disconnect a VPN user"""
        if connection_id in self.vpn_connections:
            connection = self.vpn_connections[connection_id]
            connection.status = "disconnected"
            
            logger.info("VPN user disconnected", 
                       user_id=connection.user_id,
                       username=connection.username)
            
            return True
        return False
        
    async def get_vpn_connections(self) -> List[VPNConnection]:
        """Get all VPN connections"""
        return list(self.vpn_connections.values())
        
    # NAC Management Methods
    async def add_nac_policy(self, policy_data: Dict[str, Any]) -> NACPolicy:
        """Add a new NAC policy"""
        policy = NACPolicy(
            id=policy_data["id"],
            name=policy_data["name"],
            description=policy_data["description"],
            device_requirements=policy_data["device_requirements"],
            network_access=policy_data["network_access"],
            time_restrictions=policy_data["time_restrictions"],
            enabled=policy_data["enabled"],
            priority=policy_data["priority"]
        )
        
        self.nac_policies[policy.id] = policy
        
        logger.info("NAC policy added", policy_id=policy.id, policy_name=policy.name)
        
        return policy
        
    async def evaluate_device_access(self, device_info: Dict[str, Any], 
                                   user_id: str) -> Dict[str, Any]:
        """Evaluate device access based on NAC policies"""
        # Find applicable policies
        applicable_policies = []
        
        for policy in self.nac_policies.values():
            if policy.enabled:
                # Check if device meets requirements
                if self._device_meets_requirements(device_info, policy.device_requirements):
                    applicable_policies.append(policy)
                    
        if not applicable_policies:
            return {
                "access_granted": False,
                "reason": "No applicable NAC policies found",
                "allowed_networks": []
            }
            
        # Sort by priority (lower number = higher priority)
        applicable_policies.sort(key=lambda p: p.priority)
        
        # Get allowed networks from highest priority policy
        primary_policy = applicable_policies[0]
        
        return {
            "access_granted": True,
            "policy_applied": primary_policy.name,
            "allowed_networks": primary_policy.network_access,
            "time_restrictions": primary_policy.time_restrictions
        }
        
    def _device_meets_requirements(self, device_info: Dict[str, Any], 
                                  requirements: Dict[str, Any]) -> bool:
        """Check if device meets NAC requirements"""
        for requirement, required_value in requirements.items():
            if requirement in device_info:
                if device_info[requirement] != required_value:
                    return False
            else:
                return False
        return True
        
    # DNS Security Methods
    async def check_dns_request(self, domain: str) -> Dict[str, Any]:
        """Check if DNS request should be allowed"""
        if domain in self.dns_blacklist:
            return {
                "allowed": False,
                "reason": "Domain is blacklisted",
                "action": "block"
            }
            
        if domain in self.dns_whitelist:
            return {
                "allowed": True,
                "reason": "Domain is whitelisted",
                "action": "allow"
            }
            
        # Check for suspicious patterns
        if self._is_suspicious_domain(domain):
            return {
                "allowed": False,
                "reason": "Suspicious domain pattern",
                "action": "block"
            }
            
        return {
            "allowed": True,
            "reason": "Domain is clean",
            "action": "allow"
        }
        
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain has suspicious characteristics"""
        suspicious_patterns = [
            "malware", "virus", "hack", "crack", "warez",
            "free", "download", "click", "win", "prize"
        ]
        
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in suspicious_patterns)
        
    async def add_dns_blacklist(self, domain: str) -> bool:
        """Add domain to DNS blacklist"""
        self.dns_blacklist.add(domain)
        logger.info("Domain added to blacklist", domain=domain)
        return True
        
    async def add_dns_whitelist(self, domain: str) -> bool:
        """Add domain to DNS whitelist"""
        self.dns_whitelist.add(domain)
        logger.info("Domain added to whitelist", domain=domain)
        return True
        
    # Network Segmentation Methods
    async def create_network_segment(self, segment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new network segment"""
        segment_id = segment_data["id"]
        
        self.network_segments[segment_id] = {
            "subnet": segment_data["subnet"],
            "description": segment_data["description"],
            "security_level": segment_data["security_level"],
            "allowed_services": segment_data["allowed_services"],
            "monitoring": segment_data.get("monitoring", True),
            "created_at": datetime.utcnow()
        }
        
        logger.info("Network segment created", segment_id=segment_id)
        
        return self.network_segments[segment_id]
        
    async def get_network_segments(self) -> Dict[str, Any]:
        """Get all network segments"""
        return self.network_segments
        
    # Reporting Methods
    async def get_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        current_time = datetime.utcnow()
        last_24h = current_time - timedelta(hours=24)
        
        # Get alerts from last 24 hours
        recent_alerts = [
            alert for alert in self.ids_alerts 
            if alert.timestamp > last_24h
        ]
        
        # Count alerts by severity
        severity_counts = defaultdict(int)
        for alert in recent_alerts:
            severity_counts[alert.severity.value] += 1
            
        # Count alerts by threat type
        threat_counts = defaultdict(int)
        for alert in recent_alerts:
            threat_counts[alert.threat_type.value] += 1
            
        return {
            "report_generated": current_time.isoformat(),
            "time_period": "24 hours",
            "total_alerts": len(recent_alerts),
            "severity_breakdown": dict(severity_counts),
            "threat_breakdown": dict(threat_counts),
            "active_vpn_connections": len([c for c in self.vpn_connections.values() if c.status == "connected"]),
            "blocked_ips": len(self.blocked_ips),
            "ddos_attacks": len([a for a in self.ddos_attacks if a["timestamp"] > last_24h]),
            "firewall_rules": len(self.firewall_rules),
            "nac_policies": len(self.nac_policies)
        }
        
    async def get_network_status(self) -> Dict[str, Any]:
        """Get current network security status"""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "active_threats": len([a for a in self.ids_alerts if a.status == "new"]),
            "blocked_ips_count": len(self.blocked_ips),
            "vpn_connections": len([c for c in self.vpn_connections.values() if c.status == "connected"]),
            "network_segments": len(self.network_segments),
            "firewall_rules_active": len([r for r in self.firewall_rules.values() if r.enabled]),
            "dns_blacklist_size": len(self.dns_blacklist),
            "dns_whitelist_size": len(self.dns_whitelist)
        }

# Global instance
network_security_service = NetworkSecurityService() 