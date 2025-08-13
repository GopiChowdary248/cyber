import { apiClient } from '../utils/apiClient';

export interface HealthStatus {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  version: string;
  uptime: number;
  environment: string;
}

export interface DetailedHealthStatus {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  version: string;
  uptime: number;
  environment: string;
  checks: {
    database: HealthCheck;
    redis: HealthCheck;
    external_apis: HealthCheck;
    file_system: HealthCheck;
    memory: HealthCheck;
    cpu: HealthCheck;
    disk: HealthCheck;
    network: HealthCheck;
  };
  metrics: {
    memory_usage: number;
    cpu_usage: number;
    disk_usage: number;
    active_connections: number;
    request_count: number;
    error_rate: number;
    response_time: number;
  };
}

export interface HealthCheck {
  status: 'healthy' | 'unhealthy' | 'degraded';
  message: string;
  response_time: number;
  last_check: string;
  details?: Record<string, any>;
}

export interface SystemMetrics {
  cpu: {
    usage_percent: number;
    load_average: number[];
    temperature?: number;
  };
  memory: {
    total: number;
    available: number;
    used: number;
    usage_percent: number;
    swap_total: number;
    swap_used: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    usage_percent: number;
    io_read: number;
    io_write: number;
  };
  network: {
    bytes_sent: number;
    bytes_recv: number;
    packets_sent: number;
    packets_recv: number;
    connections: number;
  };
  processes: {
    total: number;
    running: number;
    sleeping: number;
    stopped: number;
    zombie: number;
  };
}

export interface PerformanceMetrics {
  response_time: {
    p50: number;
    p90: number;
    p95: number;
    p99: number;
    average: number;
  };
  throughput: {
    requests_per_second: number;
    bytes_per_second: number;
  };
  error_rates: {
    total_errors: number;
    error_percentage: number;
    errors_by_type: Record<string, number>;
  };
  resource_utilization: {
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_usage: number;
  };
}

class HealthService {
  // Get basic health status
  async getHealthStatus(): Promise<HealthStatus> {
    const response = await apiClient.get('/health');
    return response.data;
  }

  // Get detailed health status with all checks
  async getDetailedHealthStatus(): Promise<DetailedHealthStatus> {
    const response = await apiClient.get('/health/detailed');
    return response.data;
  }

  // Get specific health check
  async getHealthCheck(checkName: string): Promise<HealthCheck> {
    const response = await apiClient.get(`/health/check/${checkName}`);
    return response.data;
  }

  // Get system metrics
  async getSystemMetrics(): Promise<SystemMetrics> {
    const response = await apiClient.get('/health/metrics/system');
    return response.data;
  }

  // Get performance metrics
  async getPerformanceMetrics(): Promise<PerformanceMetrics> {
    const response = await apiClient.get('/health/metrics/performance');
    return response.data;
  }

  // Get application metrics
  async getApplicationMetrics(): Promise<{
    version: string;
    build_date: string;
    git_commit: string;
    dependencies: Record<string, string>;
    features: string[];
    configuration: Record<string, any>;
  }> {
    const response = await apiClient.get('/health/metrics/application');
    return response.data;
  }

  // Get database health
  async getDatabaseHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    connection_count: number;
    active_queries: number;
    slow_queries: number;
    error_count: number;
    last_backup: string;
    backup_size: number;
    replication_lag?: number;
  }> {
    const response = await apiClient.get('/health/database');
    return response.data;
  }

  // Get cache health
  async getCacheHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    hit_rate: number;
    miss_rate: number;
    memory_usage: number;
    key_count: number;
    eviction_count: number;
    connection_count: number;
  }> {
    const response = await apiClient.get('/health/cache');
    return response.data;
  }

  // Get external service health
  async getExternalServiceHealth(): Promise<{
    services: Array<{
      name: string;
      url: string;
      status: 'healthy' | 'unhealthy' | 'degraded';
      response_time: number;
      last_check: string;
      error_message?: string;
    }>;
    overall_status: 'healthy' | 'unhealthy' | 'degraded';
  }> {
    const response = await apiClient.get('/health/external-services');
    return response.data;
  }

  // Get security health
  async getSecurityHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    vulnerabilities: number;
    security_updates: number;
    failed_logins: number;
    suspicious_activities: number;
    last_security_scan: string;
    compliance_score: number;
  }> {
    const response = await apiClient.get('/health/security');
    return response.data;
  }

  // Get backup health
  async getBackupHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    last_backup: string;
    backup_size: number;
    backup_duration: number;
    backup_success_rate: number;
    retention_policy: string;
    next_scheduled_backup: string;
  }> {
    const response = await apiClient.get('/health/backup');
    return response.data;
  }

  // Get network health
  async getNetworkHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    latency: number;
    packet_loss: number;
    bandwidth_usage: number;
    connection_count: number;
    firewall_status: 'active' | 'inactive' | 'error';
    ssl_certificate_expiry: string;
  }> {
    const response = await apiClient.get('/health/network');
    return response.data;
  }

  // Get storage health
  async getStorageHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    total_space: number;
    used_space: number;
    free_space: number;
    usage_percentage: number;
    io_performance: number;
    error_count: number;
    last_maintenance: string;
  }> {
    const response = await apiClient.get('/health/storage');
    return response.data;
  }

  // Get log health
  async getLogHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    log_level: string;
    log_rotation: boolean;
    log_retention_days: number;
    error_log_count: number;
    warning_log_count: number;
    last_log_cleanup: string;
  }> {
    const response = await apiClient.get('/health/logs');
    return response.data;
  }

  // Get compliance health
  async getComplianceHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    compliance_score: number;
    audit_logs: number;
    policy_violations: number;
    last_audit: string;
    next_audit: string;
    compliance_frameworks: string[];
  }> {
    const response = await apiClient.get('/health/compliance');
    return response.data;
  }

  // Get alerting health
  async getAlertingHealth(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    active_alerts: number;
    alert_channels: Array<{
      name: string;
      status: 'healthy' | 'unhealthy' | 'degraded';
      last_test: string;
    }>;
    alert_history: number;
    last_alert: string;
  }> {
    const response = await apiClient.get('/health/alerting');
    return response.data;
  }

  // Test health endpoint
  async testHealthEndpoint(): Promise<{
    success: boolean;
    response_time: number;
    status_code: number;
    message: string;
  }> {
    const startTime = Date.now();
    try {
      const response = await apiClient.get('/health');
      const endTime = Date.now();
      return {
        success: true,
        response_time: endTime - startTime,
        status_code: response.status,
        message: 'Health check successful',
      };
    } catch (error: any) {
      const endTime = Date.now();
      return {
        success: false,
        response_time: endTime - startTime,
        status_code: error.response?.status || 0,
        message: error.message || 'Health check failed',
      };
    }
  }

  // Get health history
  async getHealthHistory(
    hours: number = 24,
    interval: '1m' | '5m' | '15m' | '1h' = '15m'
  ): Promise<{
    timestamps: string[];
    statuses: string[];
    response_times: number[];
    error_counts: number[];
  }> {
    const response = await apiClient.get('/health/history', {
      params: { hours, interval },
    });
    return response.data;
  }

  // Export health report
  async exportHealthReport(
    format: 'json' | 'csv' | 'pdf' = 'json',
    includeMetrics: boolean = true
  ): Promise<Blob> {
    const response = await apiClient.get('/health/export', {
      params: { format, include_metrics: includeMetrics },
      responseType: 'blob',
    });
    return response.data;
  }
}

export const healthService = new HealthService();
export default healthService;
