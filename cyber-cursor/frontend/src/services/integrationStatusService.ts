import { apiClient } from '../utils/apiClient';

// Integration status types
export interface EndpointStatus {
  endpoint: string;
  method: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  responseTime: number;
  lastCheck: Date;
  error?: string;
  statusCode?: number;
}

export interface ServiceIntegrationStatus {
  service: string;
  endpoints: EndpointStatus[];
  overallStatus: 'healthy' | 'unhealthy' | 'partial' | 'unknown';
  lastCheck: Date;
  totalEndpoints: number;
  healthyEndpoints: number;
  unhealthyEndpoints: number;
}

export interface SystemIntegrationOverview {
  totalServices: number;
  healthyServices: number;
  unhealthyServices: number;
  partialServices: number;
  overallHealth: number; // percentage
  lastSystemCheck: Date;
  services: ServiceIntegrationStatus[];
}

// Comprehensive endpoint mapping for health checks
const ENDPOINT_HEALTH_CHECKS = {
  // Core Services
  auth: [
    { endpoint: '/auth/login', method: 'POST' },
    { endpoint: '/auth/me', method: 'GET' },
    { endpoint: '/auth/refresh', method: 'POST' }
  ],
  users: [
    { endpoint: '/users', method: 'GET' },
    { endpoint: '/users/1', method: 'GET' }
  ],
  mfa: [
    { endpoint: '/mfa/setup', method: 'GET' },
    { endpoint: '/mfa/verify', method: 'POST' }
  ],
  admin: [
    { endpoint: '/admin/dashboard', method: 'GET' },
    { endpoint: '/admin/system-status', method: 'GET' }
  ],

  // Security Testing Services
  sast: [
    { endpoint: '/sast/dashboard', method: 'GET' },
    { endpoint: '/sast/projects', method: 'GET' },
    { endpoint: '/sast/overview', method: 'GET' }
  ],
  dast: [
    { endpoint: '/dast/overview', method: 'GET' },
    { endpoint: '/dast/projects', method: 'GET' },
    { endpoint: '/dast/scans', method: 'GET' }
  ],
  rasp: [
    { endpoint: '/rasp/agents', method: 'GET' },
    { endpoint: '/rasp/dashboard/overview', method: 'GET' },
    { endpoint: '/rasp/attacks', method: 'GET' }
  ],
  application_security: [
    { endpoint: '/application-security/overview', method: 'GET' },
    { endpoint: '/application-security/vulnerabilities', method: 'GET' }
  ],

  // Cloud Security Services
  cloud_security: [
    { endpoint: '/cloud-security/configs', method: 'GET' },
    { endpoint: '/cloud-security/dashboard', method: 'GET' },
    { endpoint: '/cloud-security/findings', method: 'GET' }
  ],
  enhanced_cloud_security: [
    { endpoint: '/enhanced-cloud-security/overview', method: 'GET' },
    { endpoint: '/enhanced-cloud-security/analytics', method: 'GET' }
  ],

  // Network & Endpoint Services
  network_security: [
    { endpoint: '/network-security/devices', method: 'GET' },
    { endpoint: '/network-security/threats', method: 'GET' },
    { endpoint: '/network-security/dashboard', method: 'GET' }
  ],
  endpoint_security: [
    { endpoint: '/endpoint-security/agents', method: 'GET' },
    { endpoint: '/endpoint-security/threats', method: 'GET' }
  ],
  endpoint_antivirus_edr: [
    { endpoint: '/endpoint-antivirus-edr/status', method: 'GET' },
    { endpoint: '/endpoint-antivirus-edr/threats', method: 'GET' }
  ],
  device_control: [
    { endpoint: '/device-control/devices', method: 'GET' },
    { endpoint: '/device-control/policies', method: 'GET' }
  ],

  // Data Security Services
  data_security: [
    { endpoint: '/data-security/overview', method: 'GET' },
    { endpoint: '/data-security/encryption', method: 'GET' },
    { endpoint: '/data-security/dlp', method: 'GET' }
  ],
  data_protection: [
    { endpoint: '/data-protection/policies', method: 'GET' },
    { endpoint: '/data-protection/compliance', method: 'GET' }
  ],

  // Monitoring Services
  siem_soar: [
    { endpoint: '/siem-soar/alerts', method: 'GET' },
    { endpoint: '/siem-soar/incidents', method: 'GET' },
    { endpoint: '/siem-soar/dashboard', method: 'GET' }
  ],
  monitoring_siem_soar: [
    { endpoint: '/monitoring-siem-soar/status', method: 'GET' },
    { endpoint: '/monitoring-siem-soar/metrics', method: 'GET' }
  ],
  analytics: [
    { endpoint: '/analytics/dashboard', method: 'GET' },
    { endpoint: '/analytics/reports', method: 'GET' }
  ],
  threat_intelligence: [
    { endpoint: '/threat-intelligence/feeds', method: 'GET' },
    { endpoint: '/threat-intelligence/iocs', method: 'GET' },
    { endpoint: '/threat-intelligence/alerts', method: 'GET' }
  ],

  // Compliance Services
  compliance: [
    { endpoint: '/compliance/frameworks', method: 'GET' },
    { endpoint: '/compliance/assessments', method: 'GET' },
    { endpoint: '/compliance/reports', method: 'GET' }
  ],
  quality_goals: [
    { endpoint: '/quality-goals', method: 'GET' },
    { endpoint: '/quality-goals/metrics', method: 'GET' }
  ],

  // Workflow & Integration Services
  workflows: [
    { endpoint: '/workflows', method: 'GET' },
    { endpoint: '/workflows/templates', method: 'GET' }
  ],
  integrations: [
    { endpoint: '/integrations', method: 'GET' },
    { endpoint: '/integrations/status', method: 'GET' }
  ],

  // Dashboard & Reporting Services
  dashboard: [
    { endpoint: '/dashboard/overview', method: 'GET' },
    { endpoint: '/dashboard/analytics', method: 'GET' }
  ],
  projects: [
    { endpoint: '/projects', method: 'GET' },
    { endpoint: '/projects/1', method: 'GET' }
  ],
  reports: [
    { endpoint: '/reports', method: 'GET' },
    { endpoint: '/reports/generate', method: 'POST' }
  ],

  // Health & Monitoring
  health: [
    { endpoint: '/health', method: 'GET' },
    { endpoint: '/health/detailed', method: 'GET' }
  ],
  websocket: [
    { endpoint: '/ws/health', method: 'GET' }
  ],

  // Additional Services
  incidents: [
    { endpoint: '/incidents', method: 'GET' },
    { endpoint: '/incidents/1', method: 'GET' }
  ],
  phishing: [
    { endpoint: '/phishing/campaigns', method: 'GET' },
    { endpoint: '/phishing/reports', method: 'GET' }
  ],
  cicd: [
    { endpoint: '/cicd/pipelines', method: 'GET' },
    { endpoint: '/cicd/deployments', method: 'GET' }
  ],
  ai_ml: [
    { endpoint: '/ai-ml/models', method: 'GET' },
    { endpoint: '/ai-ml/predictions', method: 'GET' }
  ]
};

class IntegrationStatusService {
  private statusCache: Map<string, ServiceIntegrationStatus> = new Map();
  private lastSystemCheck: Date | null = null;

  /**
   * Check the health of all services and endpoints
   */
  async checkAllServices(): Promise<SystemIntegrationOverview> {
    const services = Object.keys(ENDPOINT_HEALTH_CHECKS);
    const serviceStatuses: ServiceIntegrationStatus[] = [];

    for (const service of services) {
      const status = await this.checkServiceHealth(service);
      serviceStatuses.push(status);
      this.statusCache.set(service, status);
    }

    this.lastSystemCheck = new Date();

    const healthyServices = serviceStatuses.filter(s => s.overallStatus === 'healthy').length;
    const unhealthyServices = serviceStatuses.filter(s => s.overallStatus === 'unhealthy').length;
    const partialServices = serviceStatuses.filter(s => s.overallStatus === 'partial').length;
    const overallHealth = Math.round((healthyServices / services.length) * 100);

    return {
      totalServices: services.length,
      healthyServices,
      unhealthyServices,
      partialServices,
      overallHealth,
      lastSystemCheck: this.lastSystemCheck,
      services: serviceStatuses
    };
  }

  /**
   * Check the health of a specific service
   */
  async checkServiceHealth(serviceName: string): Promise<ServiceIntegrationStatus> {
    const endpoints = ENDPOINT_HEALTH_CHECKS[serviceName as keyof typeof ENDPOINT_HEALTH_CHECKS] || [];
    const endpointStatuses: EndpointStatus[] = [];

    for (const endpoint of endpoints) {
      const status = await this.checkEndpointHealth(endpoint.endpoint, endpoint.method);
      endpointStatuses.push(status);
    }

    const healthyEndpoints = endpointStatuses.filter(e => e.status === 'healthy').length;
    const unhealthyEndpoints = endpointStatuses.filter(e => e.status === 'unhealthy').length;

    let overallStatus: 'healthy' | 'unhealthy' | 'partial' | 'unknown';
    if (healthyEndpoints === endpoints.length) {
      overallStatus = 'healthy';
    } else if (unhealthyEndpoints === endpoints.length) {
      overallStatus = 'unhealthy';
    } else if (healthyEndpoints > 0) {
      overallStatus = 'partial';
    } else {
      overallStatus = 'unknown';
    }

    return {
      service: serviceName,
      endpoints: endpointStatuses,
      overallStatus,
      lastCheck: new Date(),
      totalEndpoints: endpoints.length,
      healthyEndpoints,
      unhealthyEndpoints
    };
  }

  /**
   * Check the health of a specific endpoint
   */
  private async checkEndpointHealth(endpoint: string, method: string): Promise<EndpointStatus> {
    const startTime = Date.now();
    
    try {
      const response = await apiClient.request({
        method: method.toLowerCase() as any,
        url: endpoint,
        timeout: 5000
      });

      const responseTime = Date.now() - startTime;
      
      return {
        endpoint,
        method,
        status: 'healthy',
        responseTime,
        lastCheck: new Date(),
        statusCode: response.status
      };
    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      
      return {
        endpoint,
        method,
        status: 'unhealthy',
        responseTime,
        lastCheck: new Date(),
        error: error.message || 'Unknown error',
        statusCode: error.response?.status
      };
    }
  }

  /**
   * Get cached status for a service
   */
  getServiceStatus(serviceName: string): ServiceIntegrationStatus | undefined {
    return this.statusCache.get(serviceName);
  }

  /**
   * Get all cached service statuses
   */
  getAllCachedStatuses(): Map<string, ServiceIntegrationStatus> {
    return new Map(this.statusCache);
  }

  /**
   * Get services that need attention
   */
  getServicesNeedingAttention(): ServiceIntegrationStatus[] {
    return Array.from(this.statusCache.values()).filter(
      service => service.overallStatus === 'unhealthy' || service.overallStatus === 'partial'
    );
  }

  /**
   * Get overall system health percentage
   */
  getOverallHealthPercentage(): number {
    const services = Array.from(this.statusCache.values());
    if (services.length === 0) return 0;

    const totalEndpoints = services.reduce((sum, service) => sum + service.totalEndpoints, 0);
    const healthyEndpoints = services.reduce((sum, service) => sum + service.healthyEndpoints, 0);

    return Math.round((healthyEndpoints / totalEndpoints) * 100);
  }

  /**
   * Export integration status report
   */
  exportStatusReport(): string {
    const services = Array.from(this.statusCache.values());
    let report = `Integration Status Report\n`;
    report += `Generated: ${new Date().toISOString()}\n`;
    report += `Overall Health: ${this.getOverallHealthPercentage()}%\n\n`;

    for (const service of services) {
      report += `Service: ${service.service}\n`;
      report += `Status: ${service.overallStatus}\n`;
      report += `Endpoints: ${service.healthyEndpoints}/${service.totalEndpoints} healthy\n`;
      
      if (service.unhealthyEndpoints > 0) {
        report += `Unhealthy Endpoints:\n`;
        service.endpoints
          .filter(e => e.status === 'unhealthy')
          .forEach(e => {
            report += `  - ${e.method} ${e.endpoint}: ${e.error}\n`;
          });
      }
      report += '\n';
    }

    return report;
  }

  /**
   * Clear status cache
   */
  clearCache(): void {
    this.statusCache.clear();
    this.lastSystemCheck = null;
  }
}

export default new IntegrationStatusService();
