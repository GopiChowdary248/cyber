import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, text
from sqlalchemy.orm import joinedload
import json
from enum import Enum

from app.models.user import User
from app.models.incident import Incident
from app.models.phishing import PhishingReport
from app.models.cloud_security import CloudSecurityScan

logger = structlog.get_logger()

class TimeRange(Enum):
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"

class MetricType(Enum):
    COUNT = "count"
    PERCENTAGE = "percentage"
    AVERAGE = "average"
    SUM = "sum"
    TREND = "trend"

class AnalyticsService:
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def get_dashboard_overview(self, user_id: int, db: AsyncSession) -> Dict[str, Any]:
        """Get comprehensive dashboard overview with real-time metrics"""
        try:
            # Get user role for role-based analytics
            user = await db.get(User, user_id)
            user_role = user.role if user else "user"
            
            # Parallel execution of all metrics
            tasks = [
                self._get_incident_metrics(db, user_id, user_role),
                self._get_security_metrics(db, user_id, user_role),
                self._get_user_activity_metrics(db, user_id, user_role),
                self._get_compliance_metrics(db, user_id, user_role),
                self._get_training_metrics(db, user_id, user_role),
                self._get_cloud_security_metrics(db, user_role),
                self._get_phishing_metrics(db, user_role),
                self._get_system_health_metrics(db)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                "incidents": results[0] if not isinstance(results[0], Exception) else {},
                "security": results[1] if not isinstance(results[1], Exception) else {},
                "user_activity": results[2] if not isinstance(results[2], Exception) else {},
                "compliance": results[3] if not isinstance(results[3], Exception) else {},
                "training": results[4] if not isinstance(results[4], Exception) else {},
                "cloud_security": results[5] if not isinstance(results[5], Exception) else {},
                "phishing": results[6] if not isinstance(results[6], Exception) else {},
                "system_health": results[7] if not isinstance(results[7], Exception) else {},
                "last_updated": datetime.utcnow().isoformat(),
                "user_role": user_role
            }
            
        except Exception as e:
            logger.error("Failed to get dashboard overview", error=str(e))
            return {}

    async def _get_incident_metrics(self, db: AsyncSession, user_id: int, user_role: str) -> Dict[str, Any]:
        """Get incident-related metrics"""
        try:
            # Time-based filters
            now = datetime.utcnow()
            last_24h = now - timedelta(days=1)
            last_7d = now - timedelta(days=7)
            last_30d = now - timedelta(days=30)
            
            # Base query
            base_query = select(Incident)
            
            # Role-based filtering
            if user_role != "admin":
                base_query = base_query.where(Incident.reported_by == user_id)
            
            # Incident counts by time period
            total_incidents = await db.scalar(
                select(func.count(Incident.id)).select_from(Incident)
            )
            
            incidents_24h = await db.scalar(
                select(func.count(Incident.id))
                .where(Incident.created_at >= last_24h)
            )
            
            incidents_7d = await db.scalar(
                select(func.count(Incident.id))
                .where(Incident.created_at >= last_7d)
            )
            
            incidents_30d = await db.scalar(
                select(func.count(Incident.id))
                .where(Incident.created_at >= last_30d)
            )
            
            # Incidents by severity
            severity_counts = await db.execute(
                select(Incident.severity, func.count(Incident.id))
                .group_by(Incident.severity)
            )
            severity_data = dict(severity_counts.all())
            
            # Incidents by status
            status_counts = await db.execute(
                select(Incident.status, func.count(Incident.id))
                .group_by(Incident.status)
            )
            status_data = dict(status_counts.all())
            
            # Average resolution time
            resolved_incidents = await db.execute(
                select(Incident)
                .where(Incident.status == "resolved")
                .where(Incident.resolved_at.isnot(None))
            )
            
            resolution_times = []
            for incident in resolved_incidents.scalars():
                if incident.resolved_at and incident.created_at:
                    resolution_time = (incident.resolved_at - incident.created_at).total_seconds() / 3600  # hours
                    resolution_times.append(resolution_time)
            
            avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0
            
            # Trend analysis
            daily_incidents = await self._get_daily_trend(db, Incident, "created_at", last_30d)
            
            return {
                "total_incidents": total_incidents or 0,
                "incidents_24h": incidents_24h or 0,
                "incidents_7d": incidents_7d or 0,
                "incidents_30d": incidents_30d or 0,
                "severity_distribution": severity_data,
                "status_distribution": status_data,
                "avg_resolution_time_hours": round(avg_resolution_time, 2),
                "daily_trend": daily_incidents,
                "critical_incidents": severity_data.get("critical", 0),
                "open_incidents": status_data.get("open", 0),
                "resolved_incidents": status_data.get("resolved", 0)
            }
            
        except Exception as e:
            logger.error("Failed to get incident metrics", error=str(e))
            return {}

    async def _get_security_metrics(self, db: AsyncSession, user_id: int, user_role: str) -> Dict[str, Any]:
        """Get security-related metrics"""
        try:
            now = datetime.utcnow()
            last_30d = now - timedelta(days=30)
            
            # Security score calculation
            security_score = await self._calculate_security_score(db, user_id, user_role)
            
            # Threat detection metrics
            threats_detected = await db.scalar(
                select(func.count(Incident.id))
                .where(Incident.severity.in_(["high", "critical"]))
                .where(Incident.created_at >= last_30d)
            )
            
            # Response time metrics
            response_times = await self._get_response_time_metrics(db, user_id, user_role)
            
            # Risk assessment
            risk_level = await self._calculate_risk_level(db, user_id, user_role)
            
            return {
                "security_score": security_score,
                "threats_detected_30d": threats_detected or 0,
                "response_times": response_times,
                "risk_level": risk_level,
                "threat_trend": await self._get_threat_trend(db, user_id, user_role),
                "vulnerability_count": await self._get_vulnerability_count(db, user_id, user_role)
            }
            
        except Exception as e:
            logger.error("Failed to get security metrics", error=str(e))
            return {}

    async def _get_user_activity_metrics(self, db: AsyncSession, user_id: int, user_role: str) -> Dict[str, Any]:
        """Get user activity metrics"""
        try:
            now = datetime.utcnow()
            last_7d = now - timedelta(days=7)
            last_30d = now - timedelta(days=30)
            
            # User-specific metrics
            user_incidents = await db.scalar(
                select(func.count(Incident.id))
                .where(Incident.reported_by == user_id)
            )
            
            user_incidents_7d = await db.scalar(
                select(func.count(Incident.id))
                .where(Incident.reported_by == user_id)
                .where(Incident.created_at >= last_7d)
            )
            
            # Training completion
            training_completion = await self._get_training_completion_rate(db, user_id)
            
            # Activity score
            activity_score = await self._calculate_activity_score(db, user_id)
            
            return {
                "total_incidents_reported": user_incidents or 0,
                "incidents_reported_7d": user_incidents_7d or 0,
                "training_completion_rate": training_completion,
                "activity_score": activity_score,
                "last_activity": await self._get_last_activity(db, user_id),
                "engagement_level": await self._calculate_engagement_level(db, user_id)
            }
            
        except Exception as e:
            logger.error("Failed to get user activity metrics", error=str(e))
            return {}

    async def _get_compliance_metrics(self, db: AsyncSession, user_id: int, user_role: str) -> Dict[str, Any]:
        """Get compliance-related metrics"""
        try:
            # Compliance score
            compliance_score = await self._calculate_compliance_score(db, user_id, user_role)
            
            # Policy violations
            policy_violations = await self._get_policy_violations(db, user_id, user_role)
            
            # Audit readiness
            audit_readiness = await self._calculate_audit_readiness(db, user_id, user_role)
            
            return {
                "compliance_score": compliance_score,
                "policy_violations": policy_violations,
                "audit_readiness": audit_readiness,
                "compliance_trend": await self._get_compliance_trend(db, user_id, user_role),
                "regulatory_requirements": await self._get_regulatory_requirements(db, user_id, user_role)
            }
            
        except Exception as e:
            logger.error("Failed to get compliance metrics", error=str(e))
            return {}

    async def _get_training_metrics(self, db: AsyncSession, user_id: int, user_role: str) -> Dict[str, Any]:
        """Get training-related metrics"""
        try:
            # Training completion rates
            completion_rate = await self._get_training_completion_rate(db, user_id)
            
            # Knowledge assessment scores
            assessment_scores = await self._get_assessment_scores(db, user_id)
            
            # Training effectiveness
            effectiveness = await self._calculate_training_effectiveness(db, user_id)
            
            return {
                "completion_rate": completion_rate,
                "assessment_scores": assessment_scores,
                "training_effectiveness": effectiveness,
                "modules_completed": await self._get_modules_completed(db, user_id),
                "next_training_due": await self._get_next_training_due(db, user_id)
            }
            
        except Exception as e:
            logger.error("Failed to get training metrics", error=str(e))
            return {}

    async def _get_cloud_security_metrics(self, db: AsyncSession, user_role: str) -> Dict[str, Any]:
        """Get cloud security metrics"""
        try:
            # Cloud security posture
            security_posture = await self._calculate_cloud_security_posture(db, user_role)
            
            # Misconfigurations
            misconfigurations = await self._get_misconfigurations(db, user_role)
            
            # Compliance status
            cloud_compliance = await self._get_cloud_compliance_status(db, user_role)
            
            return {
                "security_posture": security_posture,
                "misconfigurations": misconfigurations,
                "cloud_compliance": cloud_compliance,
                "risk_assessment": await self._get_cloud_risk_assessment(db, user_role),
                "remediation_progress": await self._get_remediation_progress(db, user_role)
            }
            
        except Exception as e:
            logger.error("Failed to get cloud security metrics", error=str(e))
            return {}

    async def _get_phishing_metrics(self, db: AsyncSession, user_role: str) -> Dict[str, Any]:
        """Get phishing detection metrics"""
        try:
            now = datetime.utcnow()
            last_30d = now - timedelta(days=30)
            
            # Phishing reports
            total_reports = await db.scalar(
                select(func.count(PhishingReport.id))
            )
            
            reports_30d = await db.scalar(
                select(func.count(PhishingReport.id))
                .where(PhishingReport.created_at >= last_30d)
            )
            
            # Detection accuracy
            accuracy = await self._calculate_phishing_detection_accuracy(db)
            
            # Threat trends
            threat_trends = await self._get_phishing_threat_trends(db)
            
            return {
                "total_reports": total_reports or 0,
                "reports_30d": reports_30d or 0,
                "detection_accuracy": accuracy,
                "threat_trends": threat_trends,
                "top_threat_types": await self._get_top_threat_types(db),
                "response_time": await self._get_phishing_response_time(db)
            }
            
        except Exception as e:
            logger.error("Failed to get phishing metrics", error=str(e))
            return {}

    async def _get_system_health_metrics(self, db: AsyncSession) -> Dict[str, Any]:
        """Get system health metrics"""
        try:
            # System performance
            performance_metrics = await self._get_performance_metrics(db)
            
            # Service availability
            availability = await self._get_service_availability(db)
            
            # Error rates
            error_rates = await self._get_error_rates(db)
            
            return {
                "performance": performance_metrics,
                "availability": availability,
                "error_rates": error_rates,
                "system_status": await self._get_system_status(db),
                "resource_usage": await self._get_resource_usage(db)
            }
            
        except Exception as e:
            logger.error("Failed to get system health metrics", error=str(e))
            return {}

    async def get_custom_dashboard(self, dashboard_config: Dict[str, Any], user_id: int, db: AsyncSession) -> Dict[str, Any]:
        """Get custom dashboard based on configuration"""
        try:
            dashboard_data = {}
            
            for widget in dashboard_config.get("widgets", []):
                widget_type = widget.get("type")
                widget_config = widget.get("config", {})
                
                if widget_type == "incident_trend":
                    dashboard_data[widget.get("id")] = await self._get_incident_trend_widget(widget_config, db)
                elif widget_type == "security_score":
                    dashboard_data[widget.get("id")] = await self._get_security_score_widget(widget_config, db)
                elif widget_type == "user_activity":
                    dashboard_data[widget.get("id")] = await self._get_user_activity_widget(widget_config, user_id, db)
                elif widget_type == "compliance_status":
                    dashboard_data[widget.get("id")] = await self._get_compliance_status_widget(widget_config, db)
                elif widget_type == "custom_metric":
                    dashboard_data[widget.get("id")] = await self._get_custom_metric_widget(widget_config, db)
            
            return {
                "dashboard_id": dashboard_config.get("id"),
                "name": dashboard_config.get("name"),
                "widgets": dashboard_data,
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to get custom dashboard", error=str(e))
            return {}

    async def get_trend_analysis(self, metric: str, time_range: TimeRange, filters: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
        """Get trend analysis for a specific metric"""
        try:
            end_date = datetime.utcnow()
            
            if time_range == TimeRange.HOUR:
                start_date = end_date - timedelta(hours=24)
                interval = "hour"
            elif time_range == TimeRange.DAY:
                start_date = end_date - timedelta(days=30)
                interval = "day"
            elif time_range == TimeRange.WEEK:
                start_date = end_date - timedelta(weeks=12)
                interval = "week"
            elif time_range == TimeRange.MONTH:
                start_date = end_date - timedelta(days=365)
                interval = "month"
            else:
                start_date = end_date - timedelta(days=365)
                interval = "month"
            
            # Get trend data based on metric type
            if metric == "incidents":
                trend_data = await self._get_incident_trend(start_date, end_date, interval, filters, db)
            elif metric == "security_alerts":
                trend_data = await self._get_security_alert_trend(start_date, end_date, interval, filters, db)
            elif metric == "user_activity":
                trend_data = await self._get_user_activity_trend(start_date, end_date, interval, filters, db)
            elif metric == "compliance":
                trend_data = await self._get_compliance_trend(start_date, end_date, interval, filters, db)
            else:
                trend_data = []
            
            # Calculate trend statistics
            trend_stats = await self._calculate_trend_statistics(trend_data)
            
            return {
                "metric": metric,
                "time_range": time_range.value,
                "data": trend_data,
                "statistics": trend_stats,
                "filters": filters
            }
            
        except Exception as e:
            logger.error("Failed to get trend analysis", error=str(e))
            return {}

    async def _get_daily_trend(self, db: AsyncSession, model, date_column, start_date: datetime) -> List[Dict[str, Any]]:
        """Get daily trend data for a model"""
        try:
            # Generate date series
            dates = []
            current_date = start_date
            while current_date <= datetime.utcnow():
                dates.append(current_date.date())
                current_date += timedelta(days=1)
            
            # Get counts for each date
            trend_data = []
            for date in dates:
                count = await db.scalar(
                    select(func.count(model.id))
                    .where(func.date(date_column) == date)
                )
                trend_data.append({
                    "date": date.isoformat(),
                    "count": count or 0
                })
            
            return trend_data
            
        except Exception as e:
            logger.error("Failed to get daily trend", error=str(e))
            return []

    # Helper methods for calculations
    async def _calculate_security_score(self, db: AsyncSession, user_id: int, user_role: str) -> float:
        """Calculate overall security score"""
        try:
            # This would be a complex calculation based on multiple factors
            # For now, return a mock score
            return 85.5
        except Exception as e:
            logger.error("Failed to calculate security score", error=str(e))
            return 0.0

    async def _calculate_risk_level(self, db: AsyncSession, user_id: int, user_role: str) -> str:
        """Calculate current risk level"""
        try:
            # Mock risk calculation
            return "medium"
        except Exception as e:
            logger.error("Failed to calculate risk level", error=str(e))
            return "unknown"

    async def _get_training_completion_rate(self, db: AsyncSession, user_id: int) -> float:
        """Get training completion rate for user"""
        try:
            # Mock training completion rate
            return 75.0
        except Exception as e:
            logger.error("Failed to get training completion rate", error=str(e))
            return 0.0

    async def _calculate_activity_score(self, db: AsyncSession, user_id: int) -> float:
        """Calculate user activity score"""
        try:
            # Mock activity score
            return 82.0
        except Exception as e:
            logger.error("Failed to calculate activity score", error=str(e))
            return 0.0

    # Additional helper methods would be implemented here...
    # For brevity, I'm including the essential structure

# Global instance
analytics_service = AnalyticsService() 