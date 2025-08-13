import { apiClient, apiCallWithRetry } from '../utils/apiClient';

// Comprehensive endpoint mapping for all backend services
export const API_ENDPOINTS = {
  // Authentication & User Management
  AUTH: {
    LOGIN: '/auth/login',
    REGISTER: '/auth/register',
    REFRESH: '/auth/refresh',
    LOGOUT: '/auth/logout',
    ME: '/auth/me',
    CHANGE_PASSWORD: '/auth/change-password',
    FORGOT_PASSWORD: '/auth/forgot-password',
    RESET_PASSWORD: '/auth/reset-password',
    LOGOUT_ALL: '/auth/logout-all'
  },
  USERS: {
    LIST: '/users',
    CREATE: '/users',
    GET: (id: string) => `/users/${id}`,
    UPDATE: (id: string) => `/users/${id}`,
    DELETE: (id: string) => `/users/${id}`,
    BULK_UPDATE: '/users/bulk-update',
    BULK_DELETE: '/users/bulk-delete'
  },
  MFA: {
    SETUP: '/mfa/setup',
    VERIFY: '/mfa/verify',
    DISABLE: '/mfa/disable',
    BACKUP_CODES: '/mfa/backup-codes',
    RECOVERY: '/mfa/recovery'
  },
  ADMIN: {
    DASHBOARD: '/admin/dashboard',
    USERS: '/admin/users',
    SYSTEM_STATUS: '/admin/system-status',
    AUDIT_LOGS: '/admin/audit-logs',
    SETTINGS: '/admin/settings'
  },

  // Security Testing
  SAST: {
    DASHBOARD: '/sast/dashboard',
    OVERVIEW: '/sast/overview',
    PROJECTS: '/sast/projects',
    PROJECT: (id: string) => `/sast/projects/${id}`,
    SCANS: '/sast/scans',
    SCAN: (id: string) => `/sast/scans/${id}`,
    VULNERABILITIES: '/sast/vulnerabilities',
    SECURITY_HOTSPOTS: '/sast/security-hotspots',
    QUALITY_GATES: '/sast/quality-gates',
    CODE_COVERAGE: '/sast/code-coverage',
    DUPLICATIONS: '/sast/duplications',
    STATISTICS: '/sast/statistics',
    RULES: '/sast/rules',
    LANGUAGES: '/sast/languages',
    CONFIGURATION: (id: string) => `/sast/projects/${id}/configuration`,
    METRICS: (id: string) => `/sast/projects/${id}/metrics`,
    TRENDS: (id: string) => `/sast/projects/${id}/trends`,
    SECURITY_REPORTS: (id: string) => `/sast/projects/${id}/security-reports`,
    RELIABILITY: (id: string) => `/sast/projects/${id}/reliability`,
    MAINTAINABILITY: (id: string) => `/sast/projects/${id}/maintainability`,
    ACTIVITY: (id: string) => `/sast/projects/${id}/activity`
  },
  DAST: {
    OVERVIEW: '/dast/overview',
    PROJECTS: '/dast/projects',
    PROJECT: (id: string) => `/dast/projects/${id}`,
    SCANS: '/dast/scans',
    SCAN: (id: string) => `/dast/scans/${id}`,
    VULNERABILITIES: '/dast/vulnerabilities',
    PAYLOADS: '/dast/payloads',
    REPORTS: (id: string) => `/dast/reports/${id}`,
    WEBHOOK: '/dast/webhook'
  },
  RASP: {
    AGENTS: '/rasp/agents',
    AGENT: (id: string) => `/rasp/agents/${id}`,
    ATTACKS: '/rasp/attacks',
    ATTACK: (id: string) => `/rasp/attacks/${id}`,
    RULES: '/rasp/rules',
    RULE: (id: string) => `/rasp/rules/${id}`,
    VULNERABILITIES: '/rasp/vulnerabilities',
    VULNERABILITY: (id: string) => `/rasp/vulnerabilities/${id}`,
    VIRTUAL_PATCHES: '/rasp/virtual-patches',
    ALERTS: '/rasp/alerts',
    ALERT: (id: string) => `/rasp/alerts/${id}`,
    INTEGRATIONS: '/rasp/integrations',
    DASHBOARD_OVERVIEW: '/rasp/dashboard/overview',
    ATTACK_SUMMARY: '/rasp/dashboard/attack-summary',
    AGENT_STATUS: '/rasp/dashboard/agent-status',
    HEARTBEAT: (id: string) => `/rasp/agents/${id}/heartbeat`,
    WEBHOOK: '/rasp/webhook'
  },
  APPLICATION_SECURITY: {
    OVERVIEW: '/application-security/overview',
    VULNERABILITIES: '/application-security/vulnerabilities',
    SCANS: '/application-security/scans',
    REPORTS: '/application-security/reports',
    CONFIGURATION: '/application-security/configuration'
  },

  // Cloud Security
  CLOUD_SECURITY: {
    CONFIGS: '/cloud-security/configs',
    CONFIG: (id: string) => `/cloud-security/configs/${id}`,
    SCANS: '/cloud-security/scans',
    SCAN: (id: string) => `/cloud-security/scans/${id}`,
    FINDINGS: '/cloud-security/findings',
    FINDING: (id: string) => `/cloud-security/findings/${id}`,
    COMPLIANCE_CHECKS: '/cloud-security/compliance-checks',
    COMPLIANCE_CHECK: (id: string) => `/cloud-security/compliance-checks/${id}`,
    ASSETS: (id: string) => `/cloud-security/accounts/${id}/assets`,
    ASSET: (id: string) => `/cloud-security/accounts/${id}/assets`,
    MISCONFIGURATIONS: '/cloud-security/misconfigurations',
    SAAS_APPLICATIONS: '/cloud-security/saas-applications',
    USER_ACTIVITIES: '/cloud-security/user-activities',
    DLP_INCIDENTS: '/cloud-security/dlp-incidents',
    THREATS: '/cloud-security/threats',
    IAM_RISKS: '/cloud-security/iam-risks',
    DDOS_PROTECTION: '/cloud-security/ddos-protection',
    DASHBOARD: '/cloud-security/dashboard',
    METRICS: '/cloud-security/metrics',
    STATS: '/cloud-security/stats',
    ACTIVITY: '/cloud-security/activity',
    SCAN_INITIATE: '/cloud-security/scan/initiate',
    REMEDIATE: '/cloud-security/remediate',
    AWS_FINDINGS: (id: string) => `/cloud-security/aws/${id}/findings`,
    AWS_INSIGHTS: (id: string) => `/cloud-security/aws/${id}/insights`,
    AWS_SYNC: (id: string) => `/cloud-security/aws/${id}/sync`,
    AZURE_RECOMMENDATIONS: (id: string) => `/cloud-security/azure/${id}/recommendations`,
    AZURE_ALERTS: (id: string) => `/cloud-security/azure/${id}/alerts`,
    AZURE_SYNC: (id: string) => `/cloud-security/azure/${id}/sync`,
    GCP_FINDINGS: (id: string) => `/cloud-security/gcp/${id}/findings`,
    GCP_SOURCES: (id: string) => `/cloud-security/gcp/${id}/sources`,
    GCP_SYNC: (id: string) => `/cloud-security/gcp/${id}/sync`,
    REMEDIATE_FINDING: (id: string) => `/cloud-security/findings/${id}/remediate`,
    BULK_UPDATE: '/cloud-security/findings/bulk-update',
    EXPORT_REPORT: '/cloud-security/reports/export',
    REAL_TIME_MONITORING: (id: string) => `/cloud-security/configs/${id}/monitoring`,
    REAL_TIME_ALERTS: (id: string) => `/cloud-security/configs/${id}/alerts`,
    COST_ANALYSIS: (id: string) => `/cloud-security/accounts/${id}/cost-analysis`,
    COST_OPTIMIZATION: (id: string) => `/cloud-security/accounts/${id}/cost-optimization`,
    SUBSCRIBE_UPDATES: (id: string) => `/cloud-security/accounts/${id}/subscribe`
  },
  ENHANCED_CLOUD_SECURITY: {
    OVERVIEW: '/enhanced-cloud-security/overview',
    THREATS: '/enhanced-cloud-security/threats',
    COMPLIANCE: '/enhanced-cloud-security/compliance',
    GOVERNANCE: '/enhanced-cloud-security/governance',
    COST_MANAGEMENT: '/enhanced-cloud-security/cost-management'
  },

  // Network & Endpoint Security
  NETWORK_SECURITY: {
    OVERVIEW: '/network-security/overview',
    FIREWALLS: '/network-security/firewalls',
    INTRUSION_DETECTION: '/network-security/intrusion-detection',
    VULNERABILITY_SCANS: '/network-security/vulnerability-scans',
    PENETRATION_TESTS: '/network-security/penetration-tests',
    NETWORK_MONITORING: '/network-security/monitoring',
    TRAFFIC_ANALYSIS: '/network-security/traffic-analysis',
    THREAT_DETECTION: '/network-security/threat-detection',
    INCIDENT_RESPONSE: '/network-security/incident-response'
  },
  ENDPOINT_SECURITY: {
    OVERVIEW: '/endpoint-security/overview',
    AGENTS: '/endpoint-security/agents',
    THREATS: '/endpoint-security/threats',
    POLICIES: '/endpoint-security/policies',
    COMPLIANCE: '/endpoint-security/compliance',
    INCIDENTS: '/endpoint-security/incidents'
  },
  ENDPOINT_ANTIVIRUS_EDR: {
    OVERVIEW: '/endpoint-antivirus-edr/overview',
    SCANS: '/endpoint-antivirus-edr/scans',
    THREATS: '/endpoint-antivirus-edr/threats',
    QUARANTINE: '/endpoint-antivirus-edr/quarantine',
    POLICIES: '/endpoint-antivirus-edr/policies',
    REPORTS: '/endpoint-antivirus-edr/reports'
  },
  DEVICE_CONTROL: {
    OVERVIEW: '/device-control/overview',
    DEVICES: '/device-control/devices',
    POLICIES: '/device-control/policies',
    COMPLIANCE: '/device-control/compliance',
    REPORTS: '/device-control/reports'
  },

  // Data Security
  DATA_SECURITY: {
    OVERVIEW: '/data-security/overview',
    CLASSIFICATION: '/data-security/classification',
    ENCRYPTION: '/data-security/encryption',
    ACCESS_CONTROL: '/data-security/access-control',
    AUDIT_LOGS: '/data-security/audit-logs',
    COMPLIANCE: '/data-security/compliance',
    INCIDENTS: '/data-security/incidents'
  },
  DATA_PROTECTION: {
    OVERVIEW: '/data-protection/overview',
    BACKUP: '/data-protection/backup',
    RECOVERY: '/data-protection/recovery',
    ARCHIVING: '/data-protection/archiving',
    COMPLIANCE: '/data-protection/compliance',
    REPORTS: '/data-protection/reports'
  },

  // Monitoring & Analytics
  SIEM_SOAR: {
    OVERVIEW: '/siem-soar/overview',
    ALERTS: '/siem-soar/alerts',
    INCIDENTS: '/siem-soar/incidents',
    PLAYBOOKS: '/siem-soar/playbooks',
    INTEGRATIONS: '/siem-soar/integrations',
    REPORTS: '/siem-soar/reports'
  },
  MONITORING_SIEM_SOAR: {
    OVERVIEW: '/monitoring-siem-soar/overview',
    DASHBOARDS: '/monitoring-siem-soar/dashboards',
    ALERTS: '/monitoring-siem-soar/alerts',
    METRICS: '/monitoring-siem-soar/metrics',
    REPORTS: '/monitoring-siem-soar/reports'
  },
  ANALYTICS: {
    OVERVIEW: '/analytics/overview',
    DASHBOARDS: '/analytics/dashboards',
    REPORTS: '/analytics/reports',
    METRICS: '/analytics/metrics',
    TRENDS: '/analytics/trends',
    INSIGHTS: '/analytics/insights'
  },
  THREAT_INTELLIGENCE: {
    OVERVIEW: '/threat-intelligence/overview',
    THREATS: '/threat-intelligence/threats',
    INDICATORS: '/threat-intelligence/indicators',
    FEEDS: '/threat-intelligence/feeds',
    REPORTS: '/threat-intelligence/reports',
    INTEGRATIONS: '/threat-intelligence/integrations'
  },

  // Compliance & Governance
  COMPLIANCE: {
    OVERVIEW: '/compliance/overview',
    FRAMEWORKS: '/compliance/frameworks',
    ASSESSMENTS: '/compliance/assessments',
    REPORTS: '/compliance/reports',
    AUDITS: '/compliance/audits',
    REMEDIATION: '/compliance/remediation'
  },
  QUALITY_GOALS: {
    OVERVIEW: '/quality-goals/overview',
    GOALS: '/quality-goals/goals',
    METRICS: '/quality-goals/metrics',
    REPORTS: '/quality-goals/reports',
    DASHBOARDS: '/quality-goals/dashboards'
  },
  WORKFLOWS: {
    OVERVIEW: '/workflows/overview',
    WORKFLOWS: '/workflows/workflows',
    TEMPLATES: '/workflows/templates',
    EXECUTIONS: '/workflows/executions',
    REPORTS: '/workflows/reports'
  },

  // Incident Management
  INCIDENTS: {
    OVERVIEW: '/incidents/overview',
    INCIDENTS: '/incidents/incidents',
    INCIDENT: (id: string) => `/incidents/incidents/${id}`,
    RESPONSE: '/incidents/response',
    REPORTS: '/incidents/reports',
    METRICS: '/incidents/metrics'
  },
  PHISHING: {
    OVERVIEW: '/phishing/overview',
    DETECTIONS: '/phishing/detections',
    REPORTS: '/phishing/reports',
    TRAINING: '/phishing/training',
    METRICS: '/phishing/metrics'
  },

  // CI/CD & DevOps
  CICD: {
    OVERVIEW: '/cicd/overview',
    PIPELINES: '/cicd/pipelines',
    DEPLOYMENTS: '/cicd/deployments',
    SECURITY_SCANS: '/cicd/security-scans',
    COMPLIANCE_CHECKS: '/cicd/compliance-checks',
    REPORTS: '/cicd/reports'
  },
  INTEGRATIONS: {
    OVERVIEW: '/integrations/overview',
    INTEGRATIONS: '/integrations/integrations',
    CONFIGURATIONS: '/integrations/configurations',
    WEBHOOKS: '/integrations/webhooks',
    REPORTS: '/integrations/reports'
  },

  // Other Services
  DASHBOARD: {
    OVERVIEW: '/dashboard/overview',
    STATS: '/dashboard/stats',
    METRICS: '/dashboard/metrics',
    REPORTS: '/dashboard/reports'
  },
  PROJECTS: {
    OVERVIEW: '/projects/overview',
    PROJECTS: '/projects/projects',
    PROJECT: (id: string) => `/projects/projects/${id}`,
    MEMBERS: (id: string) => `/projects/projects/${id}/members`,
    SETTINGS: (id: string) => `/projects/projects/${id}/settings`,
    REPORTS: (id: string) => `/projects/projects/${id}/reports`
  },
  REPORTS: {
    OVERVIEW: '/reports/overview',
    REPORTS: '/reports/reports',
    REPORT: (id: string) => `/reports/reports/${id}`,
    GENERATE: '/reports/generate',
    EXPORT: '/reports/export',
    SCHEDULE: '/reports/schedule'
  },
  HEALTH: {
    STATUS: '/health/status',
    DETAILS: '/health/details',
    METRICS: '/health/metrics'
  },
  WEBSOCKET: {
    CONNECT: '/ws/connect',
    SUBSCRIBE: '/ws/subscribe',
    UNSUBSCRIBE: '/ws/unsubscribe'
  }
};

// Service mapping for frontend components
export const SERVICE_MAPPING = {
  // Core Services
  AUTH: 'authService',
  USERS: 'userService',
  MFA: 'mfaService',
  ADMIN: 'adminService',
  
  // Security Testing Services
  SAST: 'sastService',
  DAST: 'dastService',
  RASP: 'raspService',
  APPLICATION_SECURITY: 'applicationSecurityService',
  
  // Cloud Security Services
  CLOUD_SECURITY: 'cloudSecurityService',
  ENHANCED_CLOUD_SECURITY: 'enhancedCloudSecurityService',
  
  // Network & Endpoint Services
  NETWORK_SECURITY: 'networkSecurityService',
  ENDPOINT_SECURITY: 'endpointSecurityService',
  ENDPOINT_ANTIVIRUS_EDR: 'endpointAntivirusEdrService',
  DEVICE_CONTROL: 'deviceControlService',
  
  // Data Security Services
  DATA_SECURITY: 'dataSecurityService',
  DATA_PROTECTION: 'dataProtectionService',
  
  // Monitoring Services
  SIEM_SOAR: 'siemSoarService',
  MONITORING_SIEM_SOAR: 'monitoringSiemSoarService',
  ANALYTICS: 'analyticsService',
  THREAT_INTELLIGENCE: 'threatIntelligenceService',
  
  // Compliance Services
  COMPLIANCE: 'complianceService',
  QUALITY_GOALS: 'qualityGoalsService',
  WORKFLOWS: 'workflowsService',
  
  // Incident Management Services
  INCIDENTS: 'incidentService',
  PHISHING: 'phishingService',
  
  // DevOps Services
  CICD: 'cicdService',
  INTEGRATIONS: 'integrationsService',
  
  // Other Services
  DASHBOARD: 'dashboardService',
  PROJECTS: 'projectsService',
  REPORTS: 'reportsService',
  HEALTH: 'healthService',
  WEBSOCKET: 'websocketService'
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

// Main integration service class
class IntegrationService {
  private integrationStatus: Map<string, IntegrationStatus> = new Map();

  /**
   * Check the health of all backend endpoints
   */
  async checkAllEndpoints(): Promise<Map<string, IntegrationStatus>> {
    const statusChecks = Object.entries(API_ENDPOINTS).map(async ([service, endpoints]) => {
      const serviceEndpoints = Object.values(endpoints).filter(endpoint => 
        typeof endpoint === 'string' && !endpoint.includes('{')
      );
      
      for (const endpoint of serviceEndpoints) {
        // Skip function endpoints, only process string endpoints
        if (typeof endpoint !== 'string') continue;
        
        try {
          const startTime = Date.now();
          const response = await apiCallWithRetry(() => 
            apiClient.get(endpoint)
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
   * Test a specific endpoint
   */
  async testEndpoint(endpoint: string): Promise<{ success: boolean; responseTime: number; error?: string }> {
    try {
      const startTime = Date.now();
      await apiCallWithRetry(() => apiClient.get(endpoint));
      const responseTime = Date.now() - startTime;
      
      return { success: true, responseTime };
    } catch (error: any) {
      return { success: false, responseTime: 0, error: error.message };
    }
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
    
    let report = `Integration Status Report - ${new Date().toISOString()}\n`;
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
}

// Export singleton instance
export const integrationService = new IntegrationService();
export default IntegrationService;
