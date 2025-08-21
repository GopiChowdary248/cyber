"""
Celery configuration for background job processing
"""

from celery import Celery
from app.core.config import settings
import os

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.core.config')

# Create the celery app
celery_app = Celery(
    'cybershield',
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        'app.services.cspm_tasks',
        'app.services.scan_tasks',
        'app.services.remediation_tasks'
    ]
)

# Configure Celery
celery_app.conf.update(
    # Task serialization
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task routing
    task_routes={
        'app.services.cspm_tasks.*': {'queue': 'cspm'},
        'app.services.scan_tasks.*': {'queue': 'scans'},
        'app.services.remediation_tasks.*': {'queue': 'remediation'},
    },
    
    # Task execution
    task_always_eager=False,  # Set to True for testing
    task_eager_propagates=True,
    
    # Worker configuration
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    
    # Result backend
    result_expires=3600,  # 1 hour
    
    # Beat schedule (for periodic tasks)
    beat_schedule={
        'daily-security-scan': {
            'task': 'app.services.scan_tasks.run_daily_security_scan',
            'schedule': 86400.0,  # 24 hours
        },
        'compliance-check': {
            'task': 'app.services.cspm_tasks.run_compliance_check',
            'schedule': 3600.0,  # 1 hour
        },
        'risk-assessment-update': {
            'task': 'app.services.cspm_tasks.update_risk_assessments',
            'schedule': 7200.0,  # 2 hours
        },
    },
    
    # Task time limits
    task_soft_time_limit=300,  # 5 minutes
    task_time_limit=600,       # 10 minutes
    
    # Worker pool
    worker_pool='prefork',
    worker_concurrency=4,
    
    # Logging
    worker_log_format='[%(asctime)s: %(levelname)s/%(processName)s] %(message)s',
    worker_task_log_format='[%(asctime)s: %(levelname)s/%(processName)s] [%(task_name)s(%(task_id)s)] %(message)s',
)

# Auto-discover tasks in all registered app configs
celery_app.autodiscover_tasks()

if __name__ == '__main__':
    celery_app.start()
