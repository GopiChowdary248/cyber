from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
import structlog

logger = structlog.get_logger()

# Define Prometheus metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

active_incidents = Gauge(
    'active_incidents_total',
    'Total number of active incidents',
    ['severity', 'type']
)

cloud_misconfigurations = Gauge(
    'cloud_misconfigurations_total',
    'Total number of cloud misconfigurations',
    ['provider', 'severity']
)

phishing_emails_detected = Counter(
    'phishing_emails_detected_total',
    'Total number of phishing emails detected',
    ['threat_level', 'email_type']
)

ai_analysis_requests = Counter(
    'ai_analysis_requests_total',
    'Total number of AI analysis requests',
    ['analysis_type', 'status']
)

def setup_monitoring():
    """Setup monitoring and metrics collection"""
    logger.info("Setting up monitoring and metrics collection")

def get_metrics():
    """Get Prometheus metrics"""
    return generate_latest()

def record_request(method: str, endpoint: str, status: int, duration: float):
    """Record HTTP request metrics"""
    http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
    http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

def update_incident_metrics(severity: str, incident_type: str, count: int):
    """Update incident metrics"""
    active_incidents.labels(severity=severity, type=incident_type).set(count)

def update_cloud_metrics(provider: str, severity: str, count: int):
    """Update cloud security metrics"""
    cloud_misconfigurations.labels(provider=provider, severity=severity).set(count)

def record_phishing_detection(threat_level: str, email_type: str):
    """Record phishing email detection"""
    phishing_emails_detected.labels(threat_level=threat_level, email_type=email_type).inc()

def record_ai_analysis(analysis_type: str, status: str):
    """Record AI analysis requests"""
    ai_analysis_requests.labels(analysis_type=analysis_type, status=status).inc() 