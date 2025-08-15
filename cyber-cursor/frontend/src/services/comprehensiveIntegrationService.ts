import { serviceRegistry, apiCallWithRetry } from './serviceRegistry';

// Comprehensive API endpoint mapping
export const API_ENDPOINTS = {
  // Authentication & User Management
  AUTH: {
    LOGIN: '/api/v1/auth/login',
    REGISTER: '/api/v1/auth/register',
    REFRESH: '/api/v1/auth/refresh',
    LOGOUT: '/api/v1/auth/logout',
    ME: '/api/v1/auth/me',
    CHANGE_PASSWORD: '/api/v1/auth/change-password',
    FORGOT_PASSWORD: '/api/v1/auth/forgot-password',
    RESET_PASSWORD: '/api/v1/auth/reset-password',
    LOGOUT_ALL: '/api/v1/auth/logout-all'
  },
  USERS: {
    LIST: '/api/v1/users',
    CREATE: '/api/v1/users',
    GET: (id: string) => `/api/v1/users/${id}`,
    UPDATE: (id: string) => `/api/v1/users/${id}`,
    DELETE: (id: string) => `/api/v1/users/${id}`,
    BULK_UPDATE: '/api/v1/users/bulk-update',
    BULK_DELETE: '/api/v1/users/bulk-delete'
  },
  MFA: {
    SETUP: '/api/v1/mfa/setup',
    VERIFY: '/api/v1/mfa/verify',
    DISABLE: '/api/v1/mfa/disable',
    BACKUP_CODES: '/api/v1/mfa/backup-codes',
    RECOVERY: '/api/v1/mfa/recovery'
  },
  ADMIN: {
    DASHBOARD: '/api/v1/admin/dashboard',
    USERS: '/api/v1/admin/users',
    SYSTEM_STATUS: '/api/v1/admin/system-status',
    AUDIT_LOGS: '/api/v1/admin/audit-logs',
    SETTINGS: '/api/v1/admin/settings'
  },

  // Security Testing
  SAST: {
    DASHBOARD: '/api/v1/sast/dashboard',
    OVERVIEW: '/api/v1/sast/overview',
    PROJECTS: '/api/v1/sast/projects',
    PROJECT: (id: string) => `/api/v1/sast/projects/${id}`,
    SCANS: '/api/v1/sast/scans',
    SCAN: (id: string) => `/api/v1/sast/scans/${id}`,
    VULNERABILITIES: '/api/v1/sast/vulnerabilities',
    SECURITY_HOTSPOTS: '/api/v1/sast/security-hotspots',
    QUALITY_GATES: '/api/v1/sast/quality-gates',
    CODE_COVERAGE: '/api/v1/sast/code-coverage',
    DUPLICATIONS: '/api/v1/sast/duplications',
    STATISTICS: '/api/v1/sast/statistics',
    RULES: '/api/v1/sast/rules',
    LANGUAGES: '/api/v1/sast/languages',
    CONFIGURATION: (id: string) => `/api/v1/sast/projects/${id}/configuration`,
    METRICS: (id: string) => `/api/v1/sast/projects/${id}/metrics`,
    TRENDS: (id: string) => `/api/v1/sast/projects/${id}/trends`,
    SECURITY_REPORTS: (id: string) => `/api/v1/sast/projects/${id}/security-reports`,
    RELIABILITY: (id: string) => `/api/v1/sast/projects/${id}/reliability`,
    MAINTAINABILITY: (id: string) => `/api/v1/sast/projects/${id}/maintainability`,
    ACTIVITY: (id: string) => `/api/v1/sast/projects/${id}/activity`
  },
  DAST: {
    OVERVIEW: '/api/v1/dast/overview',
    PROJECTS: '/api/v1/dast/projects',
    PROJECT: (id: string) => `/api/v1/dast/projects/${id}`,
    SCANS: '/api/v1/dast/scans',
    SCAN: (id: string) => `/api/v1/dast/scans/${id}`,
    VULNERABILITIES: '/api/v1/dast/vulnerabilities',
    PAYLOADS: '/api/v1/dast/payloads',
    REPORTS: (scanId: string) => `/api/v1/dast/reports/${scanId}`,
    WEBHOOK: '/api/v1/dast/webhook'
  },
  RASP: {
    AGENTS: '/api/v1/rasp/agents',
    AGENT: (id: string) => `/api/v1/rasp/agents/${id}`,
    ATTACKS: '/api/v1/rasp/attacks',
    ATTACK: (id: string) => `/api/v1/rasp/attacks/${id}`,
    RULES: '/api/v1/rasp/rules',
    RULE: (id: string) => `/api/v1/rasp/rules/${id}`,
    VULNERABILITIES: '/api/v1/rasp/vulnerabilities',
    VULNERABILITY: (id: string) => `/api/v1/rasp/vulnerabilities/${id}`,
    VIRTUAL_PATCHES: '/api/v1/rasp/virtual-patches',
    ALERTS: '/api/v1/rasp/alerts',
    ALERT: (id: string) => `/api/v1/rasp/alerts/${id}`,
    INTEGRATIONS: '/api/v1/rasp/integrations',
    DASHBOARD_OVERVIEW: '/api/v1/rasp/dashboard/overview',
    ATTACK_SUMMARY: '/api/v1/rasp/dashboard/attack-summary',
    AGENT_STATUS: '/api/v1/rasp/dashboard/agent-status',
    HEARTBEAT: (id: string) => `/api/v1/rasp/agents/${id}/heartbeat`,
    WEBHOOK: '/api/v1/rasp/webhook'
  },
  APPLICATION_SECURITY: {
    OVERVIEW: '/api/v1/application-security/overview',
    VULNERABILITIES: '/api/v1/application-security/vulnerabilities',
    SCANS: '/api/v1/application-security/scans',
    REPORTS: '/api/v1/application-security/reports',
    CONFIGURATION: '/api/v1/application-security/configuration'
  },
  CLOUD_SECURITY: {
    OVERVIEW: '/api/v1/cloud-security/overview',
    AWS: '/api/v1/cloud-security/aws',
    AZURE: '/api/v1/cloud-security/azure',
    GCP: '/api/v1/cloud-security/gcp',
    COMPLIANCE: '/api/v1/cloud-security/compliance',
    THREAT_DETECTION: '/api/v1/cloud-security/threat-detection',
    CONFIGURATION: '/api/v1/cloud-security/configuration'
  },
  NETWORK_SECURITY: {
    OVERVIEW: '/api/v1/network-security/overview',
    FIREWALL: '/api/v1/network-security/firewall',
    IDS_IPS: '/api/v1/network-security/ids-ips',
    VPN: '/api/v1/network-security/vpn',
    MONITORING: '/api/v1/network-security/monitoring',
    THREAT_DETECTION: '/api/v1/network-security/threat-detection'
  },
  DATA_SECURITY: {
    OVERVIEW: '/api/v1/data-security/overview',
    CLASSIFICATION: '/api/v1/data-security/classification',
    ENCRYPTION: '/api/v1/data-security/encryption',
    ACCESS_CONTROL: '/api/v1/data-security/access-control',
    AUDIT: '/api/v1/data-security/audit',
    COMPLIANCE: '/api/v1/data-security/compliance'
  },
  THREAT_INTELLIGENCE: {
    OVERVIEW: '/api/v1/threat-intelligence/overview',
    FEEDS: '/api/v1/threat-intelligence/feeds',
    INDICATORS: '/api/v1/threat-intelligence/indicators',
    REPORTS: '/api/v1/threat-intelligence/reports',
    ANALYSIS: '/api/v1/threat-intelligence/analysis',
    INTEGRATIONS: '/api/v1/threat-intelligence/integrations'
  },
  INCIDENTS: {
    LIST: '/api/v1/incidents',
    CREATE: '/api/v1/incidents',
    GET: (id: string) => `/api/v1/incidents/${id}`,
    UPDATE: (id: string) => `/api/v1/incidents/${id}`,
    DELETE: (id: string) => `/api/v1/incidents/${id}`,
    ASSIGN: (id: string) => `/api/v1/incidents/${id}/assign`,
    STATUS: (id: string) => `/api/v1/incidents/${id}/status`
  },
  COMPLIANCE: {
    OVERVIEW: '/api/v1/compliance/overview',
    FRAMEWORKS: '/api/v1/compliance/frameworks',
    ASSESSMENTS: '/api/v1/compliance/assessments',
    REPORTS: '/api/v1/compliance/reports',
    REMEDIATION: '/api/v1/compliance/remediation'
  },
  WORKFLOWS: {
    LIST: '/api/v1/workflows',
    CREATE: '/api/v1/workflows',
    GET: (id: string) => `/api/v1/workflows/${id}`,
    UPDATE: (id: string) => `/api/v1/workflows/${id}`,
    DELETE: (id: string) => `/api/v1/workflows/${id}`,
    EXECUTE: (id: string) => `/api/v1/workflows/${id}/execute`,
    STATUS: (id: string) => `/api/v1/workflows/${id}/status`,
  },
  AI_ML: {
    OVERVIEW: '/api/v1/ai-ml/overview',
    MODELS: '/api/v1/ai-ml/models',
    PREDICTIONS: '/api/v1/ai-ml/predictions',
    TRAINING: '/api/v1/ai-ml/training',
    ANALYTICS: '/api/v1/ai-ml/analytics'
  },
  INTEGRATIONS: {
    LIST: '/api/v1/integrations',
    CREATE: '/api/v1/integrations',
    GET: (id: string) => `/api/v1/integrations/${id}`,
    UPDATE: (id: string) => `/api/v1/integrations/${id}`,
    DELETE: (id: string) => `/api/v1/integrations/${id}`,
    TEST: (id: string) => `/api/v1/integrations/${id}/test`,
    STATUS: (id: string) => `/api/v1/integrations/${id}/status`
  },
  PROJECTS: {
    LIST: '/api/v1/projects',
    CREATE: '/api/v1/projects',
    GET: (id: string) => `/api/v1/projects/${id}`,
    UPDATE: (id: string) => `/api/v1/projects/${id}`,
    DELETE: (id: string) => `/api/v1/projects/${id}`,
    MEMBERS: (id: string) => `/api/v1/projects/${id}/members`,
    SETTINGS: (id: string) => `/api/v1/projects/${id}/settings`
  },
  REPORTS: {
    LIST: '/api/v1/reports',
    CREATE: '/api/v1/reports',
    GET: (id: string) => `/api/v1/reports/${id}`,
    UPDATE: (id: string) => `/api/v1/reports/${id}`,
    DELETE: (id: string) => `/api/v1/reports/${id}`,
    EXPORT: (id: string) => `/api/v1/reports/${id}/export`,
    SCHEDULE: (id: string) => `/api/v1/reports/${id}/schedule`
  },
  DASHBOARD: {
    OVERVIEW: '/api/v1/dashboard/overview',
    METRICS: '/api/v1/dashboard/metrics',
    ALERTS: '/api/v1/dashboard/alerts',
    ACTIVITY: '/api/v1/dashboard/activity',
    PERFORMANCE: '/api/v1/dashboard/performance'
  },
  SECURITY: {
    OVERVIEW: '/api/v1/security/overview',
    VULNERABILITIES: '/api/v1/security/vulnerabilities',
    THREATS: '/api/v1/security/threats',
    INCIDENTS: '/api/v1/security/incidents',
    COMPLIANCE: '/api/v1/security/compliance'
  },
  WEBSOCKET: {
    CONNECT: '/api/v1/websocket/connect',
    EVENTS: '/api/v1/websocket/events',
    NOTIFICATIONS: '/api/v1/websocket/notifications'
  }
};

// Service mapping for frontend components
export const SERVICE_MAPPING = {
  'SAST': 'Static Application Security Testing',
  'DAST': 'Dynamic Application Security Testing',
  'RASP': 'Runtime Application Self-Protection',
  'CLOUD_SECURITY': 'Cloud Security',
  'NETWORK_SECURITY': 'Network Security',
  'DATA_SECURITY': 'Data Security',
  'THREAT_INTELLIGENCE': 'Threat Intelligence',
  'INCIDENTS': 'Security Incidents',
  'COMPLIANCE': 'Compliance Management',
  'WORKFLOWS': 'Security Workflows',
  'AI_ML': 'AI/ML Security',
  'INTEGRATIONS': 'Security Integrations',
  'PROJECTS': 'Project Management',
  'REPORTS': 'Security Reports',
  'DASHBOARD': 'Security Dashboard',
  'SECURITY': 'Overall Security',
  'WEBSOCKET': 'Real-time Communications'
};

// Integration status tracking
export interface IntegrationStatus {
  service: string;
  status: 'connected' | 'disconnected' | 'error' | 'unknown';
  lastCheck: Date;
  endpoint: string;
  responseTime?: number;
  error?: string;
}

// Endpoint test result
export interface EndpointTestResult {
  endpoint: string;
  method: string;
  status: 'success' | 'failed' | 'timeout' | 'unauthorized';
  responseTime: number;
  statusCode?: number;
  error?: string;
  response?: any;
}

// Service health status
export interface ServiceHealthStatus {
  service: string;
  endpoints: EndpointTestResult[];
  overallStatus: 'healthy' | 'partial' | 'unhealthy';
  successRate: number;
  averageResponseTime: number;
  lastVerified: Date;
}

// Main comprehensive integration service class
class ComprehensiveIntegrationService {
  private integrationStatus: Map<string, IntegrationStatus> = new Map();
  private serviceHealth: Map<string, ServiceHealthStatus> = new Map();

  /**
   * Check the health of all backend endpoints
   */
  async checkAllEndpoints(): Promise<Map<string, IntegrationStatus>> {
    const statusChecks = Object.entries(API_ENDPOINTS).map(async ([service, endpoints]) => {
      const serviceEndpoints = Object.values(endpoints).filter(endpoint => 
        typeof endpoint === 'string' && !endpoint.includes('{')
      );
      
      for (const endpoint of serviceEndpoints) {
        if (typeof endpoint !== 'string') continue;
        
        try {
          const startTime = Date.now();
          const response = await apiCallWithRetry(() => 
            serviceRegistry.get(endpoint)
          );
          const responseTime = Date.now() - startTime;
          
          this.integrationStatus.set(`${service}_${endpoint}`, {
            service,
            status: 'connected',
            lastCheck: new Date(),
            endpoint,
            responseTime
          });
        } catch (error: any) {
          this.integrationStatus.set(`${service}_${endpoint}`, {
            service,
            status: 'error',
            lastCheck: new Date(),
            endpoint,
            error: error.message
          });
        }
      }
    });

    await Promise.all(statusChecks);
    return this.integrationStatus;
  }

  /**
   * Test a specific service comprehensively
   */
  async testServiceComprehensive(serviceName: string): Promise<ServiceHealthStatus> {
    const endpoints = API_ENDPOINTS[serviceName as keyof typeof API_ENDPOINTS];
    if (!endpoints) {
      throw new Error(`Service ${serviceName} not found`);
    }

    const endpointResults: EndpointTestResult[] = [];
    const endpointList = Object.values(endpoints).filter(endpoint => 
      typeof endpoint === 'string' && !endpoint.includes('{')
    );

    for (const endpoint of endpointList) {
      if (typeof endpoint !== 'string') continue;
      
      const result = await this.testEndpoint(endpoint, endpoint);
      endpointResults.push(result);
    }

    const successCount = endpointResults.filter(r => r.status === 'success').length;
    const successRate = (endpointList.length > 0) ? (successCount / endpointList.length) * 100 : 0;
    const averageResponseTime = endpointResults
      .filter(r => r.responseTime > 0)
      .reduce((sum, r) => sum + r.responseTime, 0) / successCount || 0;

    const overallStatus = successRate >= 90 ? 'healthy' : 
                         successRate >= 50 ? 'partial' : 'unhealthy';

    const serviceHealth: ServiceHealthStatus = {
      service: serviceName,
      endpoints: endpointResults,
      overallStatus,
      successRate,
      averageResponseTime,
      lastVerified: new Date()
    };

    this.serviceHealth.set(serviceName, serviceHealth);
    return serviceHealth;
  }

  /**
   * Test a specific endpoint
   */
  private async testEndpoint(endpoint: string | ((id: string) => string), endpointName: string): Promise<EndpointTestResult> {
    const startTime = Date.now();
    let status: EndpointTestResult['status'] = 'success';
    let statusCode: number | undefined;
    let error: string | undefined;
    let response: any;

    try {
      const actualEndpoint = typeof endpoint === 'function' ? endpoint('test-id') : endpoint;
      
      try {
        const result = await apiCallWithRetry(() => 
          serviceRegistry.get(actualEndpoint)
        );
        statusCode = 200; // Assuming success if no error
        response = result;
      } catch (getError: any) {
        if (getError.response?.status === 405) {
          try {
            const result = await apiCallWithRetry(() => 
              serviceRegistry.post(actualEndpoint, {})
            );
            statusCode = 200; // Assuming success if no error
            response = result;
          } catch (postError: any) {
            throw postError;
          }
        } else {
          throw getError;
        }
      }

      if (statusCode >= 400) {
        status = 'failed';
        error = `HTTP ${statusCode}`;
      }
    } catch (err: any) {
      if (err.code === 'ECONNABORTED') {
        status = 'timeout';
        error = 'Request timeout';
      } else if (err.response?.status === 401) {
        status = 'unauthorized';
        error = 'Unauthorized access';
      } else {
        status = 'failed';
        error = err.message || 'Request failed';
      }
    }

    const responseTime = Date.now() - startTime;

    return {
      endpoint: endpointName,
      method: 'GET',
      status,
      responseTime,
      statusCode,
      error,
      response
    };
  }

  /**
   * Get integration status for a specific service
   */
  getServiceStatus(service: string): IntegrationStatus[] {
    return Array.from(this.integrationStatus.values())
      .filter(status => status.service === service);
  }

  /**
   * Get overall integration health
   */
  getOverallHealth(): { healthy: number; total: number; percentage: number } {
    const total = this.integrationStatus.size;
    const healthy = Array.from(this.integrationStatus.values())
      .filter(status => status.status === 'connected').length;
    
    return {
      healthy,
      total,
      percentage: total > 0 ? Math.round((healthy / total) * 100) : 0
    };
  }

  /**
   * Get all available endpoints for a service
   */
  getServiceEndpoints(service: string): Record<string, string | ((id: string) => string)> {
    return API_ENDPOINTS[service as keyof typeof API_ENDPOINTS] || {};
  }

  /**
   * Get the corresponding frontend service name
   */
  getFrontendService(backendService: string): string {
    return SERVICE_MAPPING[backendService as keyof typeof SERVICE_MAPPING] || 'unknown';
  }

  /**
   * Get all services that need attention (errors or disconnections)
   */
  getServicesNeedingAttention(): IntegrationStatus[] {
    return Array.from(this.integrationStatus.values())
      .filter(status => status.status !== 'connected');
  }

  /**
   * Export integration status report
   */
  exportStatusReport(): string {
    const health = this.getOverallHealth();
    const servicesNeedingAttention = this.getServicesNeedingAttention();
    
    let report = `Comprehensive Integration Status Report - ${new Date().toISOString()}\n`;
    report += `Overall Health: ${health.percentage}% (${health.healthy}/${health.total})\n\n`;
    
    if (servicesNeedingAttention.length > 0) {
      report += `Services Needing Attention:\n`;
      servicesNeedingAttention.forEach(status => {
        report += `- ${status.service}: ${status.status} - ${status.error || 'Unknown error'}\n`;
      });
    } else {
      report += `All services are healthy!\n`;
    }
    
    return report;
  }

  /**
   * Get service health status
   */
  getServiceHealth(serviceName: string): ServiceHealthStatus | undefined {
    return this.serviceHealth.get(serviceName);
  }

  /**
   * Get all service health statuses
   */
  getAllServiceHealth(): ServiceHealthStatus[] {
    return Array.from(this.serviceHealth.values());
  }

  /**
   * Clear cached health data
   */
  clearHealthCache(): void {
    this.serviceHealth.clear();
    this.integrationStatus.clear();
  }
}

// Export singleton instance
export const comprehensiveIntegrationService = new ComprehensiveIntegrationService();
export default ComprehensiveIntegrationService;
