import { APIService } from './APIService';

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

// Mobile-optimized endpoint mapping for health checks
const MOBILE_ENDPOINT_HEALTH_CHECKS = {
  // Core Services
  auth: [
    { endpoint: '/auth/login', method: 'POST' },
    { endpoint: '/auth/me', method: 'GET' }
  ],
  users: [
    { endpoint: '/users', method: 'GET' }
  ],
  mfa: [
    { endpoint: '/mfa/setup', method: 'GET' },
    { endpoint: '/mfa/verify', method: 'POST' }
  ],

  // Security Testing Services
  sast: [
    { endpoint: '/sast/dashboard', method: 'GET' },
    { endpoint: '/sast/projects', method: 'GET' }
  ],
  dast: [
    { endpoint: '/dast/overview', method: 'GET' },
    { endpoint: '/dast/projects', method: 'GET' }
  ],
  rasp: [
    { endpoint: '/rasp/agents', method: 'GET' },
    { endpoint: '/rasp/dashboard/overview', method: 'GET' }
  ],

  // Cloud Security Services
  cloud_security: [
    { endpoint: '/cloud-security/dashboard', method: 'GET' },
    { endpoint: '/cloud-security/findings', method: 'GET' }
  ],

  // Network & Endpoint Services
  network_security: [
    { endpoint: '/network-security/dashboard', method: 'GET' },
    { endpoint: '/network-security/threats', method: 'GET' }
  ],
  endpoint_security: [
    { endpoint: '/endpoint-security/agents', method: 'GET' }
  ],

  // Data Security Services
  data_security: [
    { endpoint: '/data-security/overview', method: 'GET' }
  ],

  // Monitoring Services
  siem_soar: [
    { endpoint: '/siem-soar/dashboard', method: 'GET' },
    { endpoint: '/siem-soar/alerts', method: 'GET' }
  ],
  threat_intelligence: [
    { endpoint: '/threat-intelligence/feeds', method: 'GET' }
  ],

  // Compliance Services
  compliance: [
    { endpoint: '/compliance/frameworks', method: 'GET' }
  ],

  // Dashboard & Reporting Services
  dashboard: [
    { endpoint: '/dashboard/overview', method: 'GET' }
  ],
  projects: [
    { endpoint: '/projects', method: 'GET' }
  ],

  // Health & Monitoring
  health: [
    { endpoint: '/health', method: 'GET' }
  ],

  // Additional Services
  incidents: [
    { endpoint: '/incidents', method: 'GET' }
  ],
  phishing: [
    { endpoint: '/phishing/campaigns', method: 'GET' }
  ]
};

class MobileIntegrationStatusService {
  private statusCache: Map<string, ServiceIntegrationStatus> = new Map();
  private lastSystemCheck: Date | null = null;
  private apiService: APIService;

  constructor() {
    this.apiService = new APIService();
  }

  /**
   * Check the health of all services and endpoints
   */
  async checkAllServices(): Promise<SystemIntegrationOverview> {
    const services = Object.keys(MOBILE_ENDPOINT_HEALTH_CHECKS);
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
    const endpoints = MOBILE_ENDPOINT_HEALTH_CHECKS[serviceName as keyof typeof MOBILE_ENDPOINT_HEALTH_CHECKS] || [];
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
      let response;
      
      if (method === 'GET') {
        response = await this.apiService.get(endpoint);
      } else if (method === 'POST') {
        response = await this.apiService.post(endpoint, {});
      } else {
        response = await this.apiService.get(endpoint);
      }

      const responseTime = Date.now() - startTime;
      
      return {
        endpoint,
        method,
        status: 'healthy',
        responseTime,
        lastCheck: new Date(),
        statusCode: response.status || 200
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
    let report = `Mobile Integration Status Report\n`;
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

  /**
   * Get quick health summary for mobile dashboard
   */
  getQuickHealthSummary(): {
    totalServices: number;
    healthyCount: number;
    unhealthyCount: number;
    overallHealth: number;
  } {
    const services = Array.from(this.statusCache.values());
    const healthyCount = services.filter(s => s.overallStatus === 'healthy').length;
    const unhealthyCount = services.filter(s => s.overallStatus === 'unhealthy').length;
    
    return {
      totalServices: services.length,
      healthyCount,
      unhealthyCount,
      overallHealth: this.getOverallHealthPercentage()
    };
  }
}

export default MobileIntegrationStatusService;
