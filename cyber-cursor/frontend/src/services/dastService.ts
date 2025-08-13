import { serviceRegistry, apiCallWithRetry } from './serviceRegistry';
import { API_ENDPOINTS } from './comprehensiveIntegrationService';

export interface DASTProject {
  id: number;
  name: string;
  description?: string;
  target_url: string;
  status: string;
  owner_id: number;
  created_at: string;
  updated_at: string;
}

export interface DASTScan {
  id: number;
  project_id: number;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  findings_count: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scan_config: {
    scan_type: string;
    max_duration: number;
    threads: number;
  };
}

export interface DASTVulnerability {
  id: number;
  scan_id: number;
  project_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  cwe_id?: string;
  cve_id?: string;
  url: string;
  parameter?: string;
  payload?: string;
  status: 'open' | 'fixed' | 'false_positive';
  created_at: string;
}

export interface DASTPayload {
  id: number;
  name: string;
  category: string;
  payload: string;
  description: string;
  risk_level: string;
}

export interface DASTReport {
  id: number;
  scan_id: number;
  project_id: number;
  generated_at: string;
  summary: {
    total_vulnerabilities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
  };
  recommendations: string[];
}

export interface DASTOverview {
  total_projects: number;
  total_scans: number;
  last_scan: string;
  active_scans: number;
}

class DASTService {
  /**
   * Get all DAST projects
   */
  async getProjects(): Promise<DASTProject[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.DAST.PROJECTS)
      );
      return response as DASTProject[];
    } catch (error) {
      console.error('Failed to fetch DAST projects:', error);
      throw error;
    }
  }

  /**
   * Create a new DAST project
   */
  async createProject(projectData: { name: string; description?: string; target_url: string }): Promise<DASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.DAST.PROJECTS, projectData)
      );
      return response as DASTProject;
    } catch (error) {
      console.error('Failed to create DAST project:', error);
      throw error;
    }
  }

  /**
   * Get DAST project by ID
   */
  async getProject(projectId: string): Promise<DASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.DAST.PROJECT(projectId))
      );
      return response as DASTProject;
    } catch (error) {
      console.error('Failed to fetch DAST project:', error);
      throw error;
    }
  }

  /**
   * Update DAST project
   */
  async updateProject(projectId: string, projectData: Partial<DASTProject>): Promise<DASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.DAST.PROJECT(projectId), projectData)
      );
      return response as DASTProject;
    } catch (error) {
      console.error('Failed to update DAST project:', error);
      throw error;
    }
  }

  /**
   * Delete DAST project
   */
  async deleteProject(projectId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        serviceRegistry.delete(API_ENDPOINTS.DAST.PROJECT(projectId))
      );
    } catch (error) {
      console.error('Failed to delete DAST project:', error);
      throw error;
    }
  }

  /**
   * Get DAST scans
   */
  async getScans(projectId?: string): Promise<DASTScan[]> {
    try {
      const endpoint = projectId 
        ? API_ENDPOINTS.DAST.SCAN(projectId)
        : API_ENDPOINTS.DAST.SCANS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint as string)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST scans:', error);
      throw error;
    }
  }

  /**
   * Start a new DAST scan
   */
  async startScan(projectId: string, scanConfig: {
    scan_type: string;
    max_duration: number;
    threads: number;
    custom_payloads?: string[];
  }): Promise<DASTScan> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.DAST.SCAN(projectId), scanConfig)
      );
      return response;
    } catch (error) {
      console.error('Failed to start DAST scan:', error);
      throw error;
    }
  }

  /**
   * Stop a running DAST scan
   */
  async stopScan(scanId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.DAST.SCAN(scanId)}/stop`)
      );
    } catch (error) {
      console.error('Failed to stop DAST scan:', error);
      throw error;
    }
  }

  /**
   * Get DAST scan status
   */
  async getScanStatus(scanId: string): Promise<DASTScan> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.DAST.SCAN(scanId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST scan status:', error);
      throw error;
    }
  }

  /**
   * Get DAST vulnerabilities
   */
  async getVulnerabilities(projectId?: string, scanId?: string): Promise<DASTVulnerability[]> {
    try {
      let endpoint = API_ENDPOINTS.DAST.VULNERABILITIES;
      if (projectId) {
        endpoint = `${API_ENDPOINTS.DAST.PROJECT(projectId)}/vulnerabilities`;
      } else if (scanId) {
        endpoint = `${API_ENDPOINTS.DAST.SCAN(scanId)}/vulnerabilities`;
      }
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST vulnerabilities:', error);
      throw error;
    }
  }

  /**
   * Update vulnerability status
   */
  async updateVulnerability(vulnerabilityId: string, status: string): Promise<DASTVulnerability> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.DAST.VULNERABILITIES, { id: vulnerabilityId, status })
      );
      return response;
    } catch (error) {
      console.error('Failed to update vulnerability:', error);
      throw error;
    }
  }

  /**
   * Get DAST payloads
   */
  async getPayloads(): Promise<DASTPayload[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.DAST.PAYLOADS)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST payloads:', error);
      throw error;
    }
  }

  /**
   * Create custom DAST payload
   */
  async createPayload(payloadData: {
    name: string;
    category: string;
    payload: string;
    description: string;
    risk_level: string;
  }): Promise<DASTPayload> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.DAST.PAYLOADS, payloadData)
      );
      return response;
    } catch (error) {
      console.error('Failed to create DAST payload:', error);
      throw error;
    }
  }

  /**
   * Get DAST reports
   */
  async getReports(projectId?: string): Promise<DASTReport[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.DAST.PROJECT(projectId)}/reports`
        : API_ENDPOINTS.DAST.REPORTS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST reports:', error);
      throw error;
    }
  }

  /**
   * Generate DAST report
   */
  async generateReport(scanId: string, format: 'pdf' | 'html' | 'json' = 'pdf'): Promise<DASTReport> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.DAST.SCAN(scanId)}/report`, { format })
      );
      return response;
    } catch (error) {
      console.error('Failed to generate DAST report:', error);
      throw error;
    }
  }

  /**
   * Get DAST overview
   */
  async getOverview(): Promise<DASTOverview> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.DAST.OVERVIEW)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST overview:', error);
      throw error;
    }
  }

  /**
   * Get DAST webhook configuration
   */
  async getWebhookConfig(): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.DAST.WEBHOOK)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST webhook config:', error);
      throw error;
    }
  }

  /**
   * Update DAST webhook configuration
   */
  async updateWebhookConfig(webhookConfig: {
    url: string;
    events: string[];
    secret?: string;
    enabled: boolean;
  }): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.DAST.WEBHOOK, webhookConfig)
      );
      return response;
    } catch (error) {
      console.error('Failed to update DAST webhook config:', error);
      throw error;
    }
  }

  /**
   * Test DAST webhook
   */
  async testWebhook(): Promise<boolean> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.DAST.WEBHOOK}/test`)
      );
      return response.success;
    } catch (error) {
      console.error('Failed to test DAST webhook:', error);
      throw error;
    }
  }

  /**
   * Get DAST scan configuration templates
   */
  async getScanTemplates(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.DAST.SCANS}/templates`)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST scan templates:', error);
      throw error;
    }
  }

  /**
   * Create DAST scan configuration template
   */
  async createScanTemplate(templateData: {
    name: string;
    description: string;
    config: any;
  }): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.DAST.SCANS}/templates`, templateData)
      );
      return response;
    } catch (error) {
      console.error('Failed to create DAST scan template:', error);
      throw error;
    }
  }

  /**
   * Schedule DAST scan
   */
  async scheduleScan(projectId: string, schedule: {
    cron: string;
    enabled: boolean;
    scan_config: any;
  }): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.DAST.PROJECT(projectId)}/schedule`, schedule)
      );
      return response;
    } catch (error) {
      console.error('Failed to schedule DAST scan:', error);
      throw error;
    }
  }

  /**
   * Get DAST scan history
   */
  async getScanHistory(projectId: string, limit: number = 50): Promise<DASTScan[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.DAST.PROJECT(projectId)}/scan-history`, {
          params: { limit }
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST scan history:', error);
      throw error;
    }
  }

  /**
   * Export DAST scan results
   */
  async exportScanResults(scanId: string, format: 'csv' | 'json' | 'xml' = 'csv'): Promise<Blob> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.DAST.SCAN(scanId)}/export`, {
          params: { format },
          responseType: 'blob'
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to export DAST scan results:', error);
      throw error;
    }
  }

  /**
   * Get DAST scan statistics
   */
  async getScanStatistics(projectId: string, timeframe: string = '30d'): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.DAST.PROJECT(projectId)}/statistics`, {
          params: { timeframe }
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch DAST scan statistics:', error);
      throw error;
    }
  }

  /**
   * Validate target URL for DAST scanning
   */
  async validateTargetUrl(url: string): Promise<{
    valid: boolean;
    accessible: boolean;
    ssl_valid: boolean;
    robots_txt?: string;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.DAST.PROJECTS}/validate-url`, { url })
      );
      return response;
    } catch (error) {
      console.error('Failed to validate target URL:', error);
      throw error;
    }
  }
}

export const dastService = new DASTService();
export default DASTService;
