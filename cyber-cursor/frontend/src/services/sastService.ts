import { serviceRegistry, apiCallWithRetry } from './serviceRegistry';
import { API_ENDPOINTS } from './comprehensiveIntegrationService';

export interface SASTProject {
  id: number;
  name: string;
  description?: string;
  status: string;
  owner_id: number;
  created_at: string;
  updated_at: string;
}

export interface SASTScan {
  id: number;
  project_id: number;
  status: string;
  started_at: string;
  completed_at?: string;
  findings_count: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface SASTVulnerability {
  id: number;
  scan_id: number;
  project_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  cwe_id?: string;
  cve_id?: string;
  file_path?: string;
  line_number?: number;
  status: 'open' | 'fixed' | 'false_positive';
  created_at: string;
}

export interface SASTDashboard {
  total_projects: number;
  total_scans: number;
  critical_vulnerabilities: number;
  last_scan: string;
}

export interface SASTMetrics {
  security_rating: string;
  reliability_rating: string;
  maintainability_rating: string;
  coverage: number;
  duplications: number;
  technical_debt: string;
}

export interface SASTQualityGate {
  id: number;
  name: string;
  status: 'passed' | 'failed' | 'warning';
  conditions: Array<{
    metric: string;
    operator: string;
    value: string;
    status: string;
  }>;
}

class SASTService {
  /**
   * Get all SAST projects
   */
  async getProjects(): Promise<SASTProject[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.PROJECTS)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST projects:', error);
      throw error;
    }
  }

  /**
   * Create a new SAST project
   */
  async createProject(projectData: { name: string; description?: string }): Promise<SASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.SAST.PROJECTS, projectData)
      );
      return response;
    } catch (error) {
      console.error('Failed to create SAST project:', error);
      throw error;
    }
  }

  /**
   * Get SAST project by ID
   */
  async getProject(projectId: string): Promise<SASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.PROJECT(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST project:', error);
      throw error;
    }
  }

  /**
   * Update SAST project
   */
  async updateProject(projectId: string, projectData: Partial<SASTProject>): Promise<SASTProject> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.SAST.PROJECT(projectId), projectData)
      );
      return response;
    } catch (error) {
      console.error('Failed to update SAST project:', error);
      throw error;
    }
  }

  /**
   * Delete SAST project
   */
  async deleteProject(projectId: string): Promise<void> {
    try {
      await apiCallWithRetry(() => 
        serviceRegistry.delete(API_ENDPOINTS.SAST.PROJECT(projectId))
      );
    } catch (error) {
      console.error('Failed to delete SAST project:', error);
      throw error;
    }
  }

  /**
   * Get SAST scans for a project
   */
  async getScans(projectId?: string): Promise<SASTScan[]> {
    try {
      const endpoint = projectId 
        ? API_ENDPOINTS.SAST.SCAN(projectId)
        : API_ENDPOINTS.SAST.SCANS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST scans:', error);
      throw error;
    }
  }

  /**
   * Start a new SAST scan
   */
  async startScan(projectId: string, scanConfig: { branch?: string; quality_gate?: boolean }): Promise<SASTScan> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(API_ENDPOINTS.SAST.SCAN(projectId), scanConfig)
      );
      return response;
    } catch (error) {
      console.error('Failed to start SAST scan:', error);
      throw error;
    }
  }

  /**
   * Get SAST vulnerabilities
   */
  async getVulnerabilities(projectId?: string): Promise<SASTVulnerability[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/vulnerabilities`
        : API_ENDPOINTS.SAST.VULNERABILITIES;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST vulnerabilities:', error);
      throw error;
    }
  }

  /**
   * Update vulnerability status
   */
  async updateVulnerability(vulnerabilityId: string, status: string): Promise<SASTVulnerability> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.SAST.VULNERABILITIES, { id: vulnerabilityId, status })
      );
      return response;
    } catch (error) {
      console.error('Failed to update vulnerability:', error);
      throw error;
    }
  }

  /**
   * Get SAST dashboard overview
   */
  async getDashboard(): Promise<SASTDashboard> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.DASHBOARD)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST dashboard:', error);
      throw error;
    }
  }

  /**
   * Get SAST overview
   */
  async getOverview(): Promise<SASTDashboard> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.OVERVIEW)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST overview:', error);
      throw error;
    }
  }

  /**
   * Get SAST metrics for a project
   */
  async getMetrics(projectId: string): Promise<SASTMetrics> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.METRICS(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST metrics:', error);
      throw error;
    }
  }

  /**
   * Get SAST quality gates
   */
  async getQualityGates(projectId?: string): Promise<SASTQualityGate[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/quality-gates`
        : API_ENDPOINTS.SAST.QUALITY_GATES;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST quality gates:', error);
      throw error;
    }
  }

  /**
   * Get SAST security hotspots
   */
  async getSecurityHotspots(projectId?: string): Promise<any[]> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/security-hotspots`
        : API_ENDPOINTS.SAST.SECURITY_HOTSPOTS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST security hotspots:', error);
      throw error;
    }
  }

  /**
   * Get SAST code coverage
   */
  async getCodeCoverage(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.CODE_COVERAGE)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST code coverage:', error);
      throw error;
    }
  }

  /**
   * Get SAST duplications
   */
  async getDuplications(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.DUPLICATIONS)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST duplications:', error);
      throw error;
    }
  }

  /**
   * Get SAST statistics
   */
  async getStatistics(projectId?: string): Promise<any> {
    try {
      const endpoint = projectId 
        ? `${API_ENDPOINTS.SAST.PROJECT(projectId)}/statistics`
        : API_ENDPOINTS.SAST.STATISTICS;
      
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(endpoint)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST statistics:', error);
      throw error;
    }
  }

  /**
   * Get SAST rules
   */
  async getRules(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.RULES)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST rules:', error);
      throw error;
    }
  }

  /**
   * Get SAST languages
   */
  async getLanguages(): Promise<any[]> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.LANGUAGES)
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST languages:', error);
      throw error;
    }
  }

  /**
   * Get SAST configuration for a project
   */
  async getConfiguration(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.CONFIGURATION(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST configuration:', error);
      throw error;
    }
  }

  /**
   * Update SAST configuration for a project
   */
  async updateConfiguration(projectId: string, config: any): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.put(API_ENDPOINTS.SAST.CONFIGURATION(projectId), config)
      );
      return response;
    } catch (error) {
      console.error('Failed to update SAST configuration:', error);
      throw error;
    }
  }

  /**
   * Get SAST trends for a project
   */
  async getTrends(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.TRENDS(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST trends:', error);
      throw error;
    }
  }

  /**
   * Get SAST security reports for a project
   */
  async getSecurityReports(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.SECURITY_REPORTS(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST security reports:', error);
      throw error;
    }
  }

  /**
   * Get SAST reliability metrics for a project
   */
  async getReliability(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.RELIABILITY(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST reliability:', error);
      throw error;
    }
  }

  /**
   * Get SAST maintainability metrics for a project
   */
  async getMaintainability(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.MAINTAINABILITY(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST maintainability:', error);
      throw error;
    }
  }

  /**
   * Get SAST activity for a project
   */
  async getActivity(projectId: string): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(API_ENDPOINTS.SAST.ACTIVITY(projectId))
      );
      return response;
    } catch (error) {
      console.error('Failed to fetch SAST activity:', error);
      throw error;
    }
  }

  /**
   * Export SAST report
   */
  async exportReport(projectId: string, format: 'pdf' | 'html' | 'json' = 'pdf'): Promise<Blob> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.get(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/export`, {
          params: { format },
          responseType: 'blob'
        })
      );
      return response;
    } catch (error) {
      console.error('Failed to export SAST report:', error);
      throw error;
    }
  }

  /**
   * Schedule SAST scan
   */
  async scheduleScan(projectId: string, schedule: { cron: string; enabled: boolean }): Promise<any> {
    try {
      const response = await apiCallWithRetry(() => 
        serviceRegistry.post(`${API_ENDPOINTS.SAST.PROJECT(projectId)}/schedule`, schedule)
      );
      return response;
    } catch (error) {
      console.error('Failed to schedule SAST scan:', error);
      throw error;
    }
  }
}

export const sastService = new SASTService();
export default SASTService;
