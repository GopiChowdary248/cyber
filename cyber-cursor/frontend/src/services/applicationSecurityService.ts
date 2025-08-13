import { apiClient } from '../utils/apiClient';

export interface Application {
  id: string;
  name: string;
  description: string;
  type: 'web' | 'mobile' | 'desktop' | 'api' | 'microservice';
  technology_stack: string[];
  version: string;
  status: 'active' | 'inactive' | 'deprecated' | 'vulnerable';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  owner: string;
  team: string;
  created_at: string;
  updated_at: string;
}

export interface ApplicationPolicy {
  id: string;
  name: string;
  description: string;
  application_id: string;
  policy_type: 'authentication' | 'authorization' | 'input_validation' | 'output_encoding' | 'session_management' | 'crypto';
  rules: ApplicationRule[];
  enabled: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
}

export interface ApplicationRule {
  id: string;
  rule_name: string;
  rule_type: string;
  pattern: string;
  action: 'allow' | 'deny' | 'log' | 'sanitize';
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  conditions: ApplicationRuleCondition[];
}

export interface ApplicationRuleCondition {
  field: string;
  operator: 'equals' | 'contains' | 'starts_with' | 'ends_with' | 'regex' | 'in_range';
  value: string | number | string[];
}

export interface ApplicationVulnerability {
  id: string;
  application_id: string;
  vulnerability_type: 'sql_injection' | 'xss' | 'csrf' | 'path_traversal' | 'command_injection' | 'authentication_bypass' | 'authorization_bypass';
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvss_score: number;
  description: string;
  location: string;
  status: 'open' | 'investigating' | 'fixing' | 'resolved' | 'false_positive';
  discovered_at: string;
  resolved_at?: string;
  remediation_steps: string[];
}

export interface ApplicationScan {
  id: string;
  application_id: string;
  scan_type: 'static' | 'dynamic' | 'dependency' | 'container' | 'infrastructure';
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  started_at: string;
  completed_at?: string;
  findings: ApplicationVulnerability[];
  scan_config: any;
}

export interface ApplicationMetrics {
  total_applications: number;
  applications_by_type: Record<string, number>;
  applications_by_risk: Record<string, number>;
  vulnerability_count: number;
  vulnerabilities_by_severity: Record<string, number>;
  compliance_rate: number;
  last_scan_date: string;
}

export interface ApplicationCompliance {
  application_id: string;
  compliance_framework: string;
  compliance_score: number;
  requirements_met: number;
  total_requirements: number;
  last_assessment: string;
  next_assessment: string;
  findings: string[];
  recommendations: string[];
}

class ApplicationSecurityService {
  private baseUrl = '/api/v1/application-security';

  // Application Management
  async getApplications(filters?: {
    type?: Application['type'];
    status?: Application['status'];
    risk_level?: Application['risk_level'];
    owner?: string;
    team?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ applications: Application[]; total: number }> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/applications`, { params: filters });
      return response.data;
    } catch (error) {
      console.error('Error fetching applications:', error);
      throw error;
    }
  }

  async getApplication(id: string): Promise<Application> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/applications/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching application:', error);
      throw error;
    }
  }

  async createApplication(application: Omit<Application, 'id' | 'created_at' | 'updated_at'>): Promise<Application> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/applications`, application);
      return response.data;
    } catch (error) {
      console.error('Error creating application:', error);
      throw error;
    }
  }

  async updateApplication(id: string, application: Partial<Application>): Promise<Application> {
    try {
      const response = await apiClient.put(`${this.baseUrl}/applications/${id}`, application);
      return response.data;
    } catch (error) {
      console.error('Error updating application:', error);
      throw error;
    }
  }

  async deleteApplication(id: string): Promise<void> {
    try {
      await apiClient.delete(`${this.baseUrl}/applications/${id}`);
    } catch (error) {
      console.error('Error deleting application:', error);
      throw error;
    }
  }

  // Application Policies
  async getPolicies(applicationId?: string): Promise<ApplicationPolicy[]> {
    try {
      const params = applicationId ? { application_id: applicationId } : {};
      const response = await apiClient.get(`${this.baseUrl}/policies`, { params });
      return response.data;
    } catch (error) {
      console.error('Error fetching application policies:', error);
      throw error;
    }
  }

  async getPolicy(id: string): Promise<ApplicationPolicy> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/policies/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching application policy:', error);
      throw error;
    }
  }

  async createPolicy(policy: Omit<ApplicationPolicy, 'id' | 'created_at' | 'updated_at'>): Promise<ApplicationPolicy> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/policies`, policy);
      return response.data;
    } catch (error) {
      console.error('Error creating application policy:', error);
      throw error;
    }
  }

  async updatePolicy(id: string, policy: Partial<ApplicationPolicy>): Promise<ApplicationPolicy> {
    try {
      const response = await apiClient.put(`${this.baseUrl}/policies/${id}`, policy);
      return response.data;
    } catch (error) {
      console.error('Error updating application policy:', error);
      throw error;
    }
  }

  async deletePolicy(id: string): Promise<void> {
    try {
      await apiClient.delete(`${this.baseUrl}/policies/${id}`);
    } catch (error) {
      console.error('Error deleting application policy:', error);
      throw error;
    }
  }

  // Application Vulnerabilities
  async getVulnerabilities(applicationId?: string, filters?: {
    severity?: ApplicationVulnerability['severity'];
    status?: ApplicationVulnerability['status'];
    vulnerability_type?: ApplicationVulnerability['vulnerability_type'];
    start_date?: string;
    end_date?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ vulnerabilities: ApplicationVulnerability[]; total: number }> {
    try {
      const params = { ...filters };
      const url = applicationId 
        ? `${this.baseUrl}/applications/${applicationId}/vulnerabilities`
        : `${this.baseUrl}/vulnerabilities`;
      const response = await apiClient.get(url, { params });
      return response.data;
    } catch (error) {
      console.error('Error fetching application vulnerabilities:', error);
      throw error;
    }
  }

  async getVulnerability(id: string): Promise<ApplicationVulnerability> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/vulnerabilities/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching application vulnerability:', error);
      throw error;
    }
  }

  async updateVulnerabilityStatus(id: string, status: ApplicationVulnerability['status']): Promise<ApplicationVulnerability> {
    try {
      const response = await apiClient.patch(`${this.baseUrl}/vulnerabilities/${id}/status`, { status });
      return response.data;
    } catch (error) {
      console.error('Error updating vulnerability status:', error);
      throw error;
    }
  }

  async addVulnerabilityRemediation(id: string, remediation: string): Promise<ApplicationVulnerability> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/vulnerabilities/${id}/remediation`, { remediation });
      return response.data;
    } catch (error) {
      console.error('Error adding vulnerability remediation:', error);
      throw error;
    }
  }

  // Application Scans
  async getScans(applicationId?: string, filters?: {
    scan_type?: ApplicationScan['scan_type'];
    status?: ApplicationScan['status'];
    start_date?: string;
    end_date?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ scans: ApplicationScan[]; total: number }> {
    try {
      const params = { ...filters };
      const url = applicationId 
        ? `${this.baseUrl}/applications/${applicationId}/scans`
        : `${this.baseUrl}/scans`;
      const response = await apiClient.get(url, { params });
      return response.data;
    } catch (error) {
      console.error('Error fetching application scans:', error);
      throw error;
    }
  }

  async getScan(id: string): Promise<ApplicationScan> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/scans/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching application scan:', error);
      throw error;
    }
  }

  async startScan(applicationId: string, scanConfig: {
    scan_type: ApplicationScan['scan_type'];
    scan_config: any;
  }): Promise<{ scan_id: string; status: string }> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/applications/${applicationId}/scans`, scanConfig);
      return response.data;
    } catch (error) {
      console.error('Error starting application scan:', error);
      throw error;
    }
  }

  async getScanStatus(scanId: string): Promise<{ status: string; progress: number; findings?: ApplicationVulnerability[] }> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/scans/${scanId}/status`);
      return response.data;
    } catch (error) {
      console.error('Error fetching scan status:', error);
      throw error;
    }
  }

  async cancelScan(scanId: string): Promise<void> {
    try {
      await apiClient.post(`${this.baseUrl}/scans/${scanId}/cancel`);
    } catch (error) {
      console.error('Error canceling scan:', error);
      throw error;
    }
  }

  // Application Compliance
  async getCompliance(applicationId: string): Promise<ApplicationCompliance[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/applications/${applicationId}/compliance`);
      return response.data;
    } catch (error) {
      console.error('Error fetching application compliance:', error);
      throw error;
    }
  }

  async getAllCompliance(): Promise<ApplicationCompliance[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/compliance`);
      return response.data;
    } catch (error) {
      console.error('Error fetching all compliance:', error);
      throw error;
    }
  }

  async runComplianceAssessment(applicationId: string, framework: string): Promise<{ assessment_id: string; status: string }> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/applications/${applicationId}/compliance-assessment`, { framework });
      return response.data;
    } catch (error) {
      console.error('Error running compliance assessment:', error);
      throw error;
    }
  }

  // Application Rules
  async getRules(): Promise<ApplicationRule[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/rules`);
      return response.data;
    } catch (error) {
      console.error('Error fetching application rules:', error);
      throw error;
    }
  }

  async createRule(rule: Omit<ApplicationRule, 'id'>): Promise<ApplicationRule> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/rules`, rule);
      return response.data;
    } catch (error) {
      console.error('Error creating application rule:', error);
      throw error;
    }
  }

  async updateRule(ruleId: string, rule: Partial<ApplicationRule>): Promise<ApplicationRule> {
    try {
      const response = await apiClient.put(`${this.baseUrl}/rules/${ruleId}`, rule);
      return response.data;
    } catch (error) {
      console.error('Error updating application rule:', error);
      throw error;
    }
  }

  async deleteRule(ruleId: string): Promise<void> {
    try {
      await apiClient.delete(`${this.baseUrl}/rules/${ruleId}`);
    } catch (error) {
      console.error('Error deleting application rule:', error);
      throw error;
    }
  }

  // Application Metrics
  async getMetrics(timeRange?: '24h' | '7d' | '30d' | '90d'): Promise<ApplicationMetrics> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/metrics`, { 
        params: { time_range: timeRange } 
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching application metrics:', error);
      throw error;
    }
  }

  async getApplicationMetrics(applicationId: string, timeRange?: '24h' | '7d' | '30d' | '90d'): Promise<ApplicationMetrics> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/applications/${applicationId}/metrics`, { 
        params: { time_range: timeRange } 
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching application metrics:', error);
      throw error;
    }
  }

  // Application Security Testing
  async runSecurityTest(applicationId: string, testType: string, testConfig: any): Promise<{ test_id: string; status: string }> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/applications/${applicationId}/security-tests`, {
        test_type: testType,
        test_config: testConfig
      });
      return response.data;
    } catch (error) {
      console.error('Error running security test:', error);
      throw error;
    }
  }

  async getSecurityTestResults(testId: string): Promise<any> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/security-tests/${testId}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching security test results:', error);
      throw error;
    }
  }

  // Bulk Operations
  async bulkUpdateApplications(applicationIds: string[], updates: Partial<Application>): Promise<Application[]> {
    try {
      const response = await apiClient.patch(`${this.baseUrl}/applications/bulk-update`, {
        application_ids: applicationIds,
        updates
      });
      return response.data;
    } catch (error) {
      console.error('Error bulk updating applications:', error);
      throw error;
    }
  }

  async bulkScanApplications(applicationIds: string[], scanConfig: any): Promise<{ scan_ids: string[]; status: string }> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/applications/bulk-scan`, {
        application_ids: applicationIds,
        scan_config: scanConfig
      });
      return response.data;
    } catch (error) {
      console.error('Error bulk scanning applications:', error);
      throw error;
    }
  }

  // Export Data
  async exportApplicationData(format: 'json' | 'csv' | 'pdf', filters?: any): Promise<Blob> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/export/applications`, { 
        params: { format, ...filters },
        responseType: 'blob'
      });
      return response.data;
    } catch (error) {
      console.error('Error exporting application data:', error);
      throw error;
    }
  }

  async exportVulnerabilityReport(format: 'json' | 'csv' | 'pdf', filters?: any): Promise<Blob> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/export/vulnerabilities`, { 
        params: { format, ...filters },
        responseType: 'blob'
      });
      return response.data;
    } catch (error) {
      console.error('Error exporting vulnerability report:', error);
      throw error;
    }
  }

  async exportComplianceReport(format: 'json' | 'csv' | 'pdf', filters?: any): Promise<Blob> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/export/compliance`, { 
        params: { format, ...filters },
        responseType: 'blob'
      });
      return response.data;
    } catch (error) {
      console.error('Error exporting compliance report:', error);
      throw error;
    }
  }
}

export const applicationSecurityService = new ApplicationSecurityService();
export default applicationSecurityService;
