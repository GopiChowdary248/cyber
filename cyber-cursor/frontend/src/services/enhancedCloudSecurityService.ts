import { apiClient } from '../utils/apiClient';

export interface ComprehensiveScanRequest {
  account_id: string;
  provider: 'aws' | 'azure' | 'gcp';
  include_cspm: boolean;
  include_casb: boolean;
  include_cloud_native: boolean;
}

export interface CSPMScanRequest {
  account_id: string;
  provider: 'aws' | 'azure' | 'gcp';
  scan_rules?: string[];
}

export interface CSPMRemediationRequest {
  finding_id: string;
  remediation_type: string;
  auto_remediate: boolean;
}

export interface CASBDiscoveryRequest {
  network_data: Record<string, any>;
}

export interface DLPScanRequest {
  file_name: string;
  file_content: string;
  file_type: string;
}

export interface CSPMFinding {
  id: string;
  account_id: string;
  provider: string;
  service: string;
  resource_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  recommendation: string;
  compliance_standards: string[];
  detected_at: string;
  status: 'open' | 'acknowledged' | 'remediated' | 'false_positive';
}

export interface CASBApplication {
  id: string;
  name: string;
  category: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  users_count: number;
  data_volume: number;
  compliance_status: string;
  last_assessment: string;
  shadow_it_score: number;
}

export interface CloudNativeStatus {
  account_id: string;
  provider: string;
  overall_score: number;
  iam_score: number;
  network_score: number;
  storage_score: number;
  compute_score: number;
  compliance_score: number;
  last_updated: string;
}

export interface IAMRisk {
  id: string;
  account_id: string;
  resource_type: string;
  resource_id: string;
  risk_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  impact: string;
  remediation: string;
  detected_at: string;
}

export interface ComplianceReport {
  standard: string;
  account_id: string;
  overall_score: number;
  passed_checks: number;
  failed_checks: number;
  total_checks: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  generated_at: string;
  details: any[];
}

export interface SecurityMetricsTrends {
  time_period: string;
  risk_score_trend: number[];
  findings_trend: number[];
  compliance_trend: number[];
  cost_optimization_trend: number[];
  dates: string[];
}

class EnhancedCloudSecurityService {
  private baseUrl = '/api/v1/enhanced-cloud-security';

  // Comprehensive Cloud Security
  async initiateComprehensiveScan(scanRequest: ComprehensiveScanRequest): Promise<{
    message: string;
    scan_id: string;
    status: string;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/scan/comprehensive`, scanRequest);
    return response.data;
  }

  async getScanStatus(scanId: string): Promise<{
    scan_id: string;
    status: string;
    progress: number;
    started_at: string;
    completed_at?: string;
    findings_count: number;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/scan/${scanId}/status`);
    return response.data;
  }

  async getComprehensiveDashboard(): Promise<any> {
    const response = await apiClient.get(`${this.baseUrl}/dashboard/comprehensive`);
    return response.data;
  }

  // CSPM (Cloud Security Posture Management)
  async initiateCSPMScan(scanRequest: CSPMScanRequest): Promise<{
    message: string;
    scan_id: string;
    status: string;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/cspm/scan`, scanRequest);
    return response.data;
  }

  async getCSPMFindings(
    accountId?: string,
    severity?: string,
    status?: string
  ): Promise<CSPMFinding[]> {
    const params = new URLSearchParams();
    if (accountId) params.append('account_id', accountId);
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    
    const response = await apiClient.get(`${this.baseUrl}/cspm/findings?${params.toString()}`);
    return response.data;
  }

  async remediateCSPMFinding(remediationRequest: CSPMRemediationRequest): Promise<{
    message: string;
    remediation_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/cspm/remediate`, remediationRequest);
    return response.data;
  }

  // CASB (Cloud Access Security Broker)
  async discoverSaaSApplications(discoveryRequest: CASBDiscoveryRequest): Promise<{
    message: string;
    discovery_id: string;
    applications_found: number;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/casb/discover`, discoveryRequest);
    return response.data;
  }

  async getSaaSApplications(status?: string, riskLevel?: string): Promise<CASBApplication[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (riskLevel) params.append('risk_level', riskLevel);
    
    const response = await apiClient.get(`${this.baseUrl}/casb/applications?${params.toString()}`);
    return response.data;
  }

  async scanForDLPViolations(dlpRequest: DLPScanRequest): Promise<{
    message: string;
    scan_id: string;
    violations_found: number;
    risk_score: number;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/casb/dlp/scan`, dlpRequest);
    return response.data;
  }

  // Cloud Native Security
  async getCloudNativeStatus(accountId: string, provider: string = 'aws'): Promise<CloudNativeStatus> {
    const response = await apiClient.get(`${this.baseUrl}/cloud-native/status/${accountId}?provider=${provider}`);
    return response.data;
  }

  async getIAMRisks(accountId?: string, severity?: string): Promise<IAMRisk[]> {
    const params = new URLSearchParams();
    if (accountId) params.append('account_id', accountId);
    if (severity) params.append('severity', severity);
    
    const response = await apiClient.get(`${this.baseUrl}/cloud-native/iam/risks?${params.toString()}`);
    return response.data;
  }

  // Compliance and Reporting
  async generateComplianceReport(
    standard: string,
    accountId?: string
  ): Promise<ComplianceReport> {
    const params = new URLSearchParams();
    params.append('standard', standard);
    if (accountId) params.append('account_id', accountId);
    
    const response = await apiClient.get(`${this.baseUrl}/compliance/report?${params.toString()}`);
    return response.data;
  }

  // Metrics and Trends
  async getSecurityMetricsTrends(days: number = 30): Promise<SecurityMetricsTrends> {
    const response = await apiClient.get(`${this.baseUrl}/metrics/trends?days=${days}`);
    return response.data;
  }

  // Risk Assessment
  async assessAccountRisk(accountId: string, provider: string = 'aws'): Promise<{
    account_id: string;
    provider: string;
    overall_risk_score: number;
    risk_factors: string[];
    recommendations: string[];
    assessment_date: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/risk-assessment`, {
      account_id: accountId,
      provider: provider
    });
    return response.data;
  }

  // Cost Optimization
  async getCostOptimizationRecommendations(accountId: string): Promise<{
    account_id: string;
    potential_savings: number;
    recommendations: Array<{
      category: string;
      description: string;
      potential_savings: number;
      effort: 'low' | 'medium' | 'high';
      priority: 'low' | 'medium' | 'high';
    }>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/cost-optimization/${accountId}`);
    return response.data;
  }

  // Security Posture Score
  async getSecurityPostureScore(accountId: string): Promise<{
    account_id: string;
    overall_score: number;
    cspm_score: number;
    casb_score: number;
    cloud_native_score: number;
    compliance_score: number;
    last_updated: string;
    trend: 'improving' | 'stable' | 'declining';
  }> {
    const response = await apiClient.get(`${this.baseUrl}/posture-score/${accountId}`);
    return response.data;
  }
}

export const enhancedCloudSecurityService = new EnhancedCloudSecurityService();
