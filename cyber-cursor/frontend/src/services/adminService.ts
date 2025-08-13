import { apiClient, apiCallWithRetry } from '../utils/apiClient';
import { API_ENDPOINTS } from './integrationService';

// Admin service interfaces
export interface AdminDashboardResponse {
  system_overview: {
    total_users: number;
    active_sessions: number;
    system_health: number;
    uptime: string;
    last_backup: string;
  };
  security_metrics: {
    total_incidents: number;
    critical_alerts: number;
    failed_logins: number;
    suspicious_activities: number;
    security_score: number;
  };
  user_management: {
    total_users: number;
    active_users: number;
    pending_approvals: number;
    recent_registrations: number;
  };
  infrastructure: {
    cloud_resources: number;
    misconfigurations: number;
    compliance_score: number;
    backup_status: string;
  };
}

export interface UserManagementResponse {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
  last_login: string;
}

export interface SystemHealthResponse {
  overall_health: number;
  services: {
    name: string;
    status: 'healthy' | 'unhealthy' | 'degraded';
    response_time: number;
    last_check: string;
  }[];
  resources: {
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_status: string;
  };
}

export interface SecurityMetricsResponse {
  incidents_by_severity: Record<string, number>;
  incidents_by_type: Record<string, number>;
  failed_logins_trend: {
    date: string;
    count: number;
  }[];
  security_score_trend: {
    date: string;
    score: number;
  }[];
}

export interface InfrastructureResponse {
  cloud_resources: {
    aws: number;
    azure: number;
    gcp: number;
    total: number;
  };
  compliance: {
    overall_score: number;
    pci_dss: number;
    sox: number;
    gdpr: number;
  };
  backup_status: {
    last_backup: string;
    next_backup: string;
    status: string;
    retention_days: number;
  };
}

export interface BroadcastAlertRequest {
  message: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Admin Service - Handles all administrative operations
 */
class AdminService {
  private baseUrl = '/admin';

  /**
   * Get admin dashboard overview
   */
  async getDashboard(): Promise<AdminDashboardResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/dashboard`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get admin dashboard:', error);
      throw error;
    }
  }

  /**
   * Get all users with filtering
   */
  async getAllUsers(params?: {
    skip?: number;
    limit?: number;
    role?: string;
    status?: string;
  }): Promise<UserManagementResponse[]> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/users`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get all users:', error);
      throw error;
    }
  }

  /**
   * Approve user registration
   */
  async approveUser(userId: number): Promise<{ message: string }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/users/${userId}/approve`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to approve user:', error);
      throw error;
    }
  }

  /**
   * Suspend user account
   */
  async suspendUser(userId: number): Promise<{ message: string }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/users/${userId}/suspend`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to suspend user:', error);
      throw error;
    }
  }

  /**
   * Get system health status
   */
  async getSystemHealth(): Promise<SystemHealthResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/system/health`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get system health:', error);
      throw error;
    }
  }

  /**
   * Get security metrics
   */
  async getSecurityMetrics(days: number = 30): Promise<SecurityMetricsResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/security/metrics`, { params: { days } })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get security metrics:', error);
      throw error;
    }
  }

  /**
   * Get infrastructure overview
   */
  async getInfrastructureOverview(): Promise<InfrastructureResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/infrastructure/overview`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get infrastructure overview:', error);
      throw error;
    }
  }

  /**
   * Trigger system backup
   */
  async triggerSystemBackup(): Promise<{ message: string }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/system/backup`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to trigger system backup:', error);
      throw error;
    }
  }

  /**
   * Get system logs
   */
  async getSystemLogs(params?: {
    level?: string;
    hours?: number;
  }): Promise<{ logs: string[] }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/logs/system`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get system logs:', error);
      throw error;
    }
  }

  /**
   * Broadcast alert to all users
   */
  async broadcastAlert(alert: BroadcastAlertRequest): Promise<{ message: string }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/alerts/broadcast`, alert)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to broadcast alert:', error);
      throw error;
    }
  }

  /**
   * Get user statistics
   */
  async getUserStatistics(): Promise<{
    total_users: number;
    active_users: number;
    inactive_users: number;
    new_users_this_month: number;
    users_by_role: Record<string, number>;
  }> {
    try {
      const users = await this.getAllUsers({ limit: 1000 });
      
      const now = new Date();
      const thisMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      
      const total_users = users.length;
      const active_users = users.filter(u => u.is_active).length;
      const inactive_users = total_users - active_users;
      const new_users_this_month = users.filter(u => 
        new Date(u.created_at) >= thisMonth
      ).length;
      
      const users_by_role = users.reduce((acc, user) => {
        acc[user.role] = (acc[user.role] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      
      return {
        total_users,
        active_users,
        inactive_users,
        new_users_this_month,
        users_by_role
      };
    } catch (error) {
      console.error('Failed to get user statistics:', error);
      throw error;
    }
  }

  /**
   * Get system performance metrics
   */
  async getSystemPerformanceMetrics(): Promise<{
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_throughput: number;
    active_connections: number;
  }> {
    try {
      const health = await this.getSystemHealth();
      const resources = health.resources;
      
      return {
        cpu_usage: resources.cpu_usage,
        memory_usage: resources.memory_usage,
        disk_usage: resources.disk_usage,
        network_throughput: 0, // Placeholder - would need additional endpoint
        active_connections: 0   // Placeholder - would need additional endpoint
      };
    } catch (error) {
      console.error('Failed to get system performance metrics:', error);
      throw error;
    }
  }

  /**
   * Get compliance overview
   */
  async getComplianceOverview(): Promise<{
    overall_score: number;
    frameworks: {
      name: string;
      score: number;
      status: 'compliant' | 'non-compliant' | 'partial';
      last_assessment: string;
    }[];
  }> {
    try {
      const infrastructure = await this.getInfrastructureOverview();
      
      return {
        overall_score: infrastructure.compliance.overall_score,
        frameworks: [
          {
            name: 'PCI DSS',
            score: infrastructure.compliance.pci_dss,
            status: infrastructure.compliance.pci_dss >= 80 ? 'compliant' : 
                    infrastructure.compliance.pci_dss >= 60 ? 'partial' : 'non-compliant',
            last_assessment: new Date().toISOString() // Placeholder
          },
          {
            name: 'SOX',
            score: infrastructure.compliance.sox,
            status: infrastructure.compliance.sox >= 80 ? 'compliant' : 
                    infrastructure.compliance.sox >= 60 ? 'partial' : 'non-compliant',
            last_assessment: new Date().toISOString() // Placeholder
          },
          {
            name: 'GDPR',
            score: infrastructure.compliance.gdpr,
            status: infrastructure.compliance.gdpr >= 80 ? 'compliant' : 
                    infrastructure.compliance.gdpr >= 60 ? 'partial' : 'non-compliant',
            last_assessment: new Date().toISOString() // Placeholder
          }
        ]
      };
    } catch (error) {
      console.error('Failed to get compliance overview:', error);
      throw error;
    }
  }

  /**
   * Get audit trail
   */
  async getAuditTrail(params?: {
    start_date?: string;
    end_date?: string;
    user_id?: number;
    action?: string;
    limit?: number;
  }): Promise<{
    actions: Array<{
      id: number;
      user_id: number;
      username: string;
      action: string;
      resource: string;
      timestamp: string;
      ip_address: string;
      details: Record<string, any>;
    }>;
    total: number;
  }> {
    try {
      // This would need a corresponding backend endpoint
      // For now, return placeholder data
      return {
        actions: [],
        total: 0
      };
    } catch (error) {
      console.error('Failed to get audit trail:', error);
      throw error;
    }
  }

  /**
   * Export admin report
   */
  async exportAdminReport(): Promise<{
    dashboard: AdminDashboardResponse;
    system_health: SystemHealthResponse;
    security_metrics: SecurityMetricsResponse;
    infrastructure: InfrastructureResponse;
    user_statistics: any;
    compliance_overview: any;
    timestamp: string;
  }> {
    try {
      const [
        dashboard,
        system_health,
        security_metrics,
        infrastructure,
        user_statistics,
        compliance_overview
      ] = await Promise.all([
        this.getDashboard(),
        this.getSystemHealth(),
        this.getSecurityMetrics(),
        this.getInfrastructureOverview(),
        this.getUserStatistics(),
        this.getComplianceOverview()
      ]);

      return {
        dashboard,
        system_health,
        security_metrics,
        infrastructure,
        user_statistics,
        compliance_overview,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Failed to export admin report:', error);
      throw error;
    }
  }
}

export default new AdminService();
