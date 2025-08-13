import { apiClient, apiCallWithRetry } from '../utils/apiClient';
import { API_ENDPOINTS, SERVICE_MAPPING } from './integrationService';

// Integration verification interfaces
export interface EndpointTestResult {
  endpoint: string;
  method: string;
  status: 'success' | 'failed' | 'timeout' | 'unauthorized';
  responseTime: number;
  statusCode?: number;
  error?: string;
  response?: any;
}

export interface ServiceIntegrationStatus {
  service: string;
  endpoints: EndpointTestResult[];
  overallStatus: 'healthy' | 'partial' | 'unhealthy';
  successRate: number;
  averageResponseTime: number;
  lastVerified: Date;
}

export interface IntegrationReport {
  timestamp: Date;
  overallHealth: 'healthy' | 'partial' | 'unhealthy';
  services: ServiceIntegrationStatus[];
  summary: {
    totalEndpoints: number;
    successfulEndpoints: number;
    failedEndpoints: number;
    averageResponseTime: number;
  };
}

class IntegrationVerificationService {
  private verificationResults: Map<string, ServiceIntegrationStatus> = new Map();
  private isVerifying: boolean = false;

  /**
   * Verify all service integrations comprehensively
   */
  async verifyAllIntegrations(): Promise<IntegrationReport> {
    if (this.isVerifying) {
      throw new Error('Verification already in progress');
    }

    this.isVerifying = true;
    const startTime = Date.now();

    try {
      const services = Object.values(SERVICE_MAPPING);
      const serviceResults: ServiceIntegrationStatus[] = [];

      for (const serviceName of services) {
        const serviceStatus = await this.verifyServiceIntegration(serviceName);
        serviceResults.push(serviceStatus);
        this.verificationResults.set(serviceName, serviceStatus);
      }

      const report = this.generateIntegrationReport(serviceResults, startTime);
      return report;
    } finally {
      this.isVerifying = false;
    }
  }

  /**
   * Verify integration for a specific service
   */
  async verifyServiceIntegration(serviceName: string): Promise<ServiceIntegrationStatus> {
    const endpoints = this.getServiceEndpoints(serviceName);
    const endpointResults: EndpointTestResult[] = [];

    for (const [endpointName, endpoint] of Object.entries(endpoints)) {
      try {
        const result = await this.testEndpoint(endpoint, endpointName);
        endpointResults.push(result);
      } catch (error) {
        endpointResults.push({
          endpoint: endpointName,
          method: 'GET',
          status: 'failed',
          responseTime: 0,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    const successCount = endpointResults.filter(r => r.status === 'success').length;
    const successRate = (successCount / endpointResults.length) * 100;
    const averageResponseTime = endpointResults
      .filter(r => r.responseTime > 0)
      .reduce((sum, r) => sum + r.responseTime, 0) / successCount || 0;

    const overallStatus = successRate >= 90 ? 'healthy' : 
                         successRate >= 50 ? 'partial' : 'unhealthy';

    return {
      service: serviceName,
      endpoints: endpointResults,
      overallStatus,
      successRate,
      averageResponseTime,
      lastVerified: new Date()
    };
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
      // Handle dynamic endpoints with IDs
      const actualEndpoint = typeof endpoint === 'function' ? endpoint('test-id') : endpoint;
      
      // Test with GET method first, fallback to POST for endpoints that require it
      try {
        const result = await apiCallWithRetry(() => 
          apiClient.get(actualEndpoint, { timeout: 10000 })
        );
        statusCode = result.status;
        response = result.data;
      } catch (getError: any) {
        if (getError.response?.status === 405) {
          // Method not allowed, try POST
          try {
            const result = await apiCallWithRetry(() => 
              apiClient.post(actualEndpoint, {}, { timeout: 10000 })
            );
            statusCode = result.status;
            response = result.data;
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
   * Get all endpoints for a specific service
   */
  private getServiceEndpoints(serviceName: string): Record<string, string | ((id: string) => string)> {
    // Map service names to their corresponding API endpoint groups
    const serviceEndpointMap: Record<string, keyof typeof API_ENDPOINTS> = {
      'sastService': 'SAST',
      'dastService': 'DAST',
      'raspService': 'RASP',
      'cloudSecurityService': 'CLOUD_SECURITY',
      'enhancedCloudSecurityService': 'ENHANCED_CLOUD_SECURITY',
      'networkSecurityService': 'NETWORK_SECURITY',
      'endpointSecurityService': 'ENDPOINT_SECURITY',
      'endpointAntivirusEdrService': 'ENDPOINT_ANTIVIRUS_EDR',
      'deviceControlService': 'DEVICE_CONTROL',
      'dataSecurityService': 'DATA_SECURITY',
      'dataProtectionService': 'DATA_PROTECTION',
      'siemSoarService': 'SIEM_SOAR',
      'monitoringSiemSoarService': 'MONITORING_SIEM_SOAR',
      'analyticsService': 'ANALYTICS',
      'threatIntelligenceService': 'THREAT_INTELLIGENCE',
      'complianceService': 'COMPLIANCE',
      'qualityGoalsService': 'QUALITY_GOALS',
      'workflowsService': 'WORKFLOWS',
      'incidentService': 'INCIDENTS',
      'phishingService': 'PHISHING',
      'cicdService': 'CICD',
      'integrationsService': 'INTEGRATIONS',
      'dashboardService': 'DASHBOARD',
      'projectsService': 'PROJECTS',
      'reportsService': 'REPORTS',
      'healthService': 'HEALTH',
      'websocketService': 'WEBSOCKET',
      'authService': 'AUTH',
      'userService': 'USERS',
      'mfaService': 'MFA',
      'adminService': 'ADMIN',
      'applicationSecurityService': 'APPLICATION_SECURITY'
    };

    const endpointGroup = serviceEndpointMap[serviceName];
    if (!endpointGroup) {
      return {};
    }

    return API_ENDPOINTS[endpointGroup] || {};
  }

  /**
   * Generate comprehensive integration report
   */
  private generateIntegrationReport(services: ServiceIntegrationStatus[], startTime: number): IntegrationReport {
    const totalEndpoints = services.reduce((sum, s) => sum + s.endpoints.length, 0);
    const successfulEndpoints = services.reduce((sum, s) => sum + s.endpoints.filter(e => e.status === 'success').length, 0);
    const failedEndpoints = totalEndpoints - successfulEndpoints;
    
    const allResponseTimes = services.flatMap(s => s.endpoints.filter(e => e.responseTime > 0).map(e => e.responseTime));
    const averageResponseTime = allResponseTimes.length > 0 ? 
      allResponseTimes.reduce((sum, time) => sum + time, 0) / allResponseTimes.length : 0;

    const overallHealth = successfulEndpoints / totalEndpoints >= 0.9 ? 'healthy' :
                         successfulEndpoints / totalEndpoints >= 0.5 ? 'partial' : 'unhealthy';

    return {
      timestamp: new Date(),
      overallHealth,
      services,
      summary: {
        totalEndpoints,
        successfulEndpoints,
        failedEndpoints,
        averageResponseTime
      }
    };
  }

  /**
   * Get verification results for a specific service
   */
  getServiceVerificationResults(serviceName: string): ServiceIntegrationStatus | undefined {
    return this.verificationResults.get(serviceName);
  }

  /**
   * Get all verification results
   */
  getAllVerificationResults(): Map<string, ServiceIntegrationStatus> {
    return new Map(this.verificationResults);
  }

  /**
   * Export verification report as JSON
   */
  exportVerificationReport(): string {
    const report = {
      timestamp: new Date().toISOString(),
      services: Array.from(this.verificationResults.values())
    };
    return JSON.stringify(report, null, 2);
  }

  /**
   * Get services that need attention
   */
  getServicesNeedingAttention(): ServiceIntegrationStatus[] {
    return Array.from(this.verificationResults.values())
      .filter(service => service.overallStatus === 'unhealthy' || service.overallStatus === 'partial');
  }

  /**
   * Get overall system health percentage
   */
  getOverallSystemHealth(): number {
    if (this.verificationResults.size === 0) return 0;
    
    const totalServices = this.verificationResults.size;
    const healthyServices = Array.from(this.verificationResults.values())
      .filter(service => service.overallStatus === 'healthy').length;
    
    return (healthyServices / totalServices) * 100;
  }
}

// Export singleton instance
const integrationVerificationService = new IntegrationVerificationService();
export default integrationVerificationService;
