import { apiClient, apiCallWithRetry } from '../utils/apiClient';

// Enums matching backend schemas
export enum CloudProvider {
  AWS = "aws",
  AZURE = "azure",
  GCP = "gcp",
  MULTI_CLOUD = "multi_cloud"
}

export enum SecurityStatus {
  SECURE = "secure",
  WARNING = "warning",
  CRITICAL = "critical",
  UNKNOWN = "unknown"
}

export enum ComplianceStatus {
  COMPLIANT = "compliant",
  NON_COMPLIANT = "non_compliant",
  PARTIALLY_COMPLIANT = "partially_compliant",
  NOT_ASSESSED = "not_assessed"
}

export enum RiskLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical"
}

// AWS Security Hub interfaces
export interface AWSSecurityFinding {
  id: string;
  arn: string;
  title: string;
  description: string;
  severity: string;
  finding_provider_fields: Record<string, any>;
  resources: Record<string, any>[];
  created_at: string;
  updated_at: string;
  status: string;
  workflow_state: string;
  remediation: Record<string, any>;
  compliance: Record<string, any>;
}

export interface AWSSecurityHubInsight {
  id: string;
  name: string;
  filters: Record<string, any>;
  group_by_attribute: string;
  insight_arn: string;
  created_at: string;
  updated_at: string;
}

// Azure Security Center interfaces
export interface AzureSecurityRecommendation {
  id: string;
  name: string;
  type: string;
  category: string;
  severity: string;
  status: string;
  description: string;
  remediation_steps: string[];
  affected_resources: string[];
  created_at: string;
  updated_at: string;
}

export interface AzureSecurityAlert {
  id: string;
  name: string;
  severity: string;
  status: string;
  category: string;
  description: string;
  affected_resources: string[];
  created_at: string;
  updated_at: string;
}

// GCP Security Command Center interfaces
export interface GCPSecurityFinding {
  id: string;
  name: string;
  parent: string;
  resource_name: string;
  state: string;
  category: string;
  severity: string;
  description: string;
  source_properties: Record<string, any>;
  event_time: string;
  create_time: string;
  update_time: string;
}

export interface GCPSecuritySource {
  id: string;
  name: string;
  display_name: string;
  description: string;
  canonical_name: string;
  organization_id: string;
}

// General cloud security interfaces
export interface CloudSecurityConfig {
  id: number;
  provider: CloudProvider;
  account_id: string;
  account_name: string;
  region: string;
  is_active: boolean;
  credentials_configured: boolean;
  last_sync: string;
  sync_frequency: number; // minutes
  config_metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface CloudSecurityScan {
  id: number;
  config_id: number;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  findings_count: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  scan_metadata: Record<string, any>;
  error_message?: string;
}

export interface CloudSecurityFinding {
  id: number;
  scan_id: number;
  provider: CloudProvider;
  finding_id: string;
  title: string;
  description: string;
  severity: SecurityStatus;
  risk_level: RiskLevel;
  category: string;
  resource_id: string;
  resource_type: string;
  region: string;
  account_id: string;
  compliance_frameworks: string[];
  remediation_steps: string[];
  references: string[];
  created_at: string;
  updated_at: string;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  assigned_to?: number;
  notes?: string;
}

export interface CloudComplianceCheck {
  id: number;
  config_id: number;
  framework: string;
  control_id: string;
  control_name: string;
  description: string;
  status: ComplianceStatus;
  severity: RiskLevel;
  assessment_date: string;
  next_assessment_date: string;
  findings: number;
  compliant_resources: number;
  non_compliant_resources: number;
  evidence: Record<string, any>;
  remediation_guidance: string;
}

export interface CloudSecurityDashboard {
  total_accounts: number;
  active_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  compliance_score: number;
  risk_score: number;
  last_scan: string;
  findings_by_provider: Record<string, number>;
  findings_by_category: Record<string, number>;
  compliance_by_framework: Record<string, number>;
  recent_activity: CloudSecurityActivity[];
}

export interface CloudSecurityActivity {
  id: number;
  type: string;
  description: string;
  severity: SecurityStatus;
  timestamp: string;
  account_id: string;
  provider: CloudProvider;
  details: Record<string, any>;
}

// Create and update interfaces
export interface CloudSecurityConfigCreate {
  provider: CloudProvider;
  account_id: string;
  account_name: string;
  region: string;
  credentials: Record<string, any>;
  sync_frequency?: number;
  config_metadata?: Record<string, any>;
}

export interface CloudSecurityConfigUpdate {
  account_name?: string;
  region?: string;
  is_active?: boolean;
  sync_frequency?: number;
  config_metadata?: Record<string, any>;
}

export interface CloudSecurityScanCreate {
  config_id: number;
  scan_type: string;
  scan_metadata?: Record<string, any>;
}

export interface CloudSecurityFindingUpdate {
  status?: 'open' | 'investigating' | 'resolved' | 'false_positive';
  assigned_to?: number;
  notes?: string;
  risk_level?: RiskLevel;
}

// Filter and search interfaces
export interface CloudSecurityFilter {
  provider?: CloudProvider;
  severity?: SecurityStatus;
  risk_level?: RiskLevel;
  status?: string;
  category?: string;
  region?: string;
  account_id?: string;
  date_from?: string;
  date_to?: string;
  compliance_framework?: string;
  search?: string;
}

export interface CloudSecurityStats {
  total_findings: number;
  findings_by_severity: Record<string, number>;
  findings_by_provider: Record<string, number>;
  findings_by_category: Record<string, number>;
  compliance_score: number;
  risk_score: number;
  findings_trend: Record<string, number>[];
  top_vulnerabilities: string[];
  compliance_by_framework: Record<string, number>;
}

class CloudSecurityService {
  // Cloud Account Management
  async getCloudSecurityConfigs(): Promise<CloudSecurityConfig[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get('/cloud-security/accounts')
    );
    return response.data;
  }

  async getCloudSecurityConfig(configId: number): Promise<CloudSecurityConfig> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/accounts/${configId}`)
    );
    return response.data;
  }

  async createCloudSecurityConfig(configData: CloudSecurityConfigCreate): Promise<CloudSecurityConfig> {
    const response = await apiCallWithRetry(() => 
      apiClient.post('/cloud-security/accounts', configData)
    );
    return response.data;
  }

  async updateCloudSecurityConfig(configId: number, updateData: CloudSecurityConfigUpdate): Promise<CloudSecurityConfig> {
    const response = await apiCallWithRetry(() => 
      apiClient.put(`/cloud-security/accounts/${configId}`, updateData)
    );
    return response.data;
  }

  async deleteCloudSecurityConfig(configId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.delete(`/cloud-security/accounts/${configId}`)
    );
    return response.data;
  }

  async testCloudSecurityConfig(configId: number): Promise<{ success: boolean; message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/accounts/${configId}/test`)
    );
    return response.data;
  }

  // Cloud Asset Management
  async getCloudAssets(accountId: number, assetType?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (assetType) params.append('asset_type', assetType);

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/accounts/${accountId}/assets?${params.toString()}`)
    );
    return response.data;
  }

  async createCloudAsset(accountId: number, assetData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/accounts/${accountId}/assets`, assetData)
    );
    return response.data;
  }

  // Cloud Security Scans
  async getCloudSecurityScans(configId?: number): Promise<CloudSecurityScan[]> {
    const params = new URLSearchParams();
    if (configId) params.append('config_id', configId.toString());

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/scans?${params.toString()}`)
    );
    return response.data;
  }

  async getCloudSecurityScan(scanId: number): Promise<CloudSecurityScan> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/scans/${scanId}`)
    );
    return response.data;
  }

  async createCloudSecurityScan(scanData: CloudSecurityScanCreate): Promise<CloudSecurityScan> {
    const response = await apiCallWithRetry(() => 
      apiClient.post('/cloud-security/scans', scanData)
    );
    return response.data;
  }

  async startCloudSecurityScan(scanId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/scans/${scanId}/start`)
    );
    return response.data;
  }

  async stopCloudSecurityScan(scanId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/scans/${scanId}/stop`)
    );
    return response.data;
  }

  async deleteCloudSecurityScan(scanId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.delete(`/cloud-security/scans/${scanId}`)
    );
    return response.data;
  }

  // Cloud Security Findings
  async getCloudSecurityFindings(
    skip: number = 0,
    limit: number = 100,
    filter?: CloudSecurityFilter
  ): Promise<{ findings: CloudSecurityFinding[]; total: number }> {
    const params = new URLSearchParams();
    if (skip > 0) params.append('skip', skip.toString());
    if (limit !== 100) params.append('limit', limit.toString());
    
    if (filter) {
      Object.entries(filter).forEach(([key, value]) => {
        if (value !== undefined) params.append(key, value.toString());
      });
    }

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/findings?${params.toString()}`)
    );
    return response.data;
  }

  async getCloudSecurityFinding(findingId: number): Promise<CloudSecurityFinding> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/findings/${findingId}`)
    );
    return response.data;
  }

  async updateCloudSecurityFinding(findingId: number, updateData: CloudSecurityFindingUpdate): Promise<CloudSecurityFinding> {
    const response = await apiCallWithRetry(() => 
      apiClient.put(`/cloud-security/findings/${findingId}`, updateData)
    );
    return response.data;
  }

  async deleteCloudSecurityFinding(findingId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.delete(`/cloud-security/findings/${findingId}`)
    );
    return response.data;
  }

  // Cloud Compliance
  async getCloudComplianceChecks(configId?: number): Promise<CloudComplianceCheck[]> {
    const params = new URLSearchParams();
    if (configId) params.append('config_id', configId.toString());

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/compliance?${params.toString()}`)
    );
    return response.data;
  }

  async getCloudComplianceCheck(checkId: number): Promise<CloudComplianceCheck> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/compliance/${checkId}`)
    );
    return response.data;
  }

  async runComplianceAssessment(configId: number, frameworks?: string[]): Promise<{ message: string; assessment_id: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/compliance/assess`, { config_id: configId, frameworks })
    );
    return response.data;
  }

  // Cloud Misconfigurations
  async getMisconfigurations(severity?: string, status?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/misconfigurations?${params.toString()}`)
    );
    return response.data;
  }

  async createMisconfiguration(assetId: number, misconfigData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/misconfigurations?asset_id=${assetId}`, misconfigData)
    );
    return response.data;
  }

  // SaaS Applications
  async getSaaSApplications(status?: string, category?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (category) params.append('category', category);

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/saas-applications?${params.toString()}`)
    );
    return response.data;
  }

  async createSaaSApplication(appData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post('/cloud-security/saas-applications', appData)
    );
    return response.data;
  }

  // User Activities
  async createUserActivity(appId: number, activityData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/user-activities?app_id=${appId}`, activityData)
    );
    return response.data;
  }

  // DLP Incidents
  async createDLPIncident(appId: number, incidentData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/dlp-incidents?app_id=${appId}`, incidentData)
    );
    return response.data;
  }

  // Cloud Threats
  async getCloudThreats(accountId?: number, severity?: string, status?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (accountId) params.append('account_id', accountId.toString());
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/threats?${params.toString()}`)
    );
    return response.data;
  }

  async createCloudThreat(accountId: number, threatData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/threats?account_id=${accountId}`, threatData)
    );
    return response.data;
  }

  // IAM Risks
  async createIAMRisk(accountId: number, riskData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/iam-risks?account_id=${accountId}`, riskData)
    );
    return response.data;
  }

  // DDoS Protection
  async createDDoSProtection(accountId: number, protectionData: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/ddos-protection?account_id=${accountId}`, protectionData)
    );
    return response.data;
  }

  // Dashboard & Analytics
  async getCloudSecurityDashboard(): Promise<CloudSecurityDashboard> {
    const response = await apiCallWithRetry(() => 
      apiClient.get('/cloud-security/dashboard/overview')
    );
    return response.data;
  }

  async getCloudSecurityMetrics(): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.get('/cloud-security/dashboard/metrics')
    );
    return response.data;
  }

  async getCloudSecurityStats(filter?: CloudSecurityFilter): Promise<CloudSecurityStats> {
    const params = new URLSearchParams();
    if (filter) {
      Object.entries(filter).forEach(([key, value]) => {
        if (value !== undefined) params.append(key, value.toString());
      });
    }

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/stats?${params.toString()}`)
    );
    return response.data;
  }

  async getCloudSecurityActivity(
    skip: number = 0,
    limit: number = 100
  ): Promise<CloudSecurityActivity[]> {
    const params = new URLSearchParams();
    if (skip > 0) params.append('skip', skip.toString());
    if (limit !== 100) params.append('limit', limit.toString());

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/activity?${params.toString()}`)
    );
    return response.data;
  }

  // Cloud Security Operations
  async initiateCloudScan(scanRequest: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post('/cloud-security/scan', scanRequest)
    );
    return response.data;
  }

  async remediateMisconfiguration(remediationRequest: any): Promise<any> {
    const response = await apiCallWithRetry(() => 
      apiClient.post('/cloud-security/remediate', remediationRequest)
    );
    return response.data;
  }

  // Provider-specific integrations
  async getAWSSecurityFindings(accountId: string): Promise<AWSSecurityFinding[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/aws/${accountId}/findings`)
    );
    return response.data;
  }

  async getAWSSecurityInsights(accountId: string): Promise<AWSSecurityHubInsight[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/aws/${accountId}/insights`)
    );
    return response.data;
  }

  async syncAWSSecurityHub(accountId: string): Promise<{ message: string; findings_count: number }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/aws/${accountId}/sync`)
    );
    return response.data;
  }

  async getAzureSecurityRecommendations(accountId: string): Promise<AzureSecurityRecommendation[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/azure/${accountId}/recommendations`)
    );
    return response.data;
  }

  async getAzureSecurityAlerts(accountId: string): Promise<AzureSecurityAlert[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/azure/${accountId}/alerts`)
    );
    return response.data;
  }

  async syncAzureSecurityCenter(accountId: string): Promise<{ message: string; recommendations_count: number }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/azure/${accountId}/sync`)
    );
    return response.data;
  }

  async getGCPSecurityFindings(projectId: string): Promise<GCPSecurityFinding[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/gcp/${projectId}/findings`)
    );
    return response.data;
  }

  async getGCPSecuritySources(projectId: string): Promise<GCPSecuritySource[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/gcp/${projectId}/sources`)
    );
    return response.data;
  }

  async syncGCPSecurityCommandCenter(projectId: string): Promise<{ message: string; findings_count: number }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/gcp/${projectId}/sync`)
    );
    return response.data;
  }

  // Advanced Operations
  async remediateCloudSecurityFinding(findingId: number, action: string): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/findings/${findingId}/remediate`, { action })
    );
    return response.data;
  }

  async bulkUpdateFindings(findingIds: number[], updates: CloudSecurityFindingUpdate): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.put('/cloud-security/findings/bulk', { finding_ids: findingIds, updates })
    );
    return response.data;
  }

  async exportCloudSecurityReport(
    format: 'csv' | 'json' | 'pdf' = 'csv',
    filter?: CloudSecurityFilter
  ): Promise<Blob> {
    const params = new URLSearchParams();
    params.append('format', format);
    if (filter) {
      Object.entries(filter).forEach(([key, value]) => {
        if (value !== undefined) params.append(key, value.toString());
      });
    }

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/export?${params.toString()}`, {
        responseType: 'blob'
      })
    );
    return response.data;
  }

  // Real-time Monitoring
  async enableRealTimeMonitoring(configId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/monitoring/${configId}/enable`)
    );
    return response.data;
  }

  async disableRealTimeMonitoring(configId: number): Promise<{ message: string }> {
    const response = await apiCallWithRetry(() => 
      apiClient.post(`/cloud-security/monitoring/${configId}/disable`)
    );
    return response.data;
  }

  async getRealTimeAlerts(configId: number): Promise<Record<string, any>[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/monitoring/${configId}/alerts`)
    );
    return response.data;
  }

  // Cost Analysis
  async getCloudCostAnalysis(accountId: string, dateFrom?: string, dateTo?: string): Promise<Record<string, any>> {
    const params = new URLSearchParams();
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/cost/${accountId}?${params.toString()}`)
    );
    return response.data;
  }

  async getCostOptimizationRecommendations(accountId: string): Promise<Record<string, any>[]> {
    const response = await apiCallWithRetry(() => 
      apiClient.get(`/cloud-security/cost/${accountId}/optimization`)
    );
    return response.data;
  }

  // WebSocket for real-time updates
  async subscribeToCloudSecurityUpdates(accountId: string, callback: (data: any) => void): Promise<void> {
    const ws = new WebSocket(`ws://localhost:8000/ws/cloud-security/${accountId}`);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      callback(data);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    return new Promise((resolve) => {
      ws.onopen = () => resolve();
    });
  }

  // CASB Provider Data
  async getCASBProviderData(provider: string): Promise<{
    name: string;
    status: string;
    last_sync: string;
    total_apps_monitored: number;
    blocked_apps: number;
    allowed_apps: number;
    dlp_violations: number;
    threat_detections: number;
  }> {
    try {
      const response = await apiClient.get(`/api/v1/cloud/casb/provider/${provider}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching CASB provider data:', error);
      throw error;
    }
  }

  // Cloud Apps Management
  async getCloudApps(): Promise<{
    id: string;
    name: string;
    category: string;
    risk_level: string;
    users_count: number;
    data_volume: string;
    last_activity: string;
    status: string;
  }[]> {
    try {
      const response = await apiClient.get('/api/v1/cloud/apps');
      return response.data;
    } catch (error) {
      console.error('Error fetching cloud apps:', error);
      throw error;
    }
  }

  async blockCloudApp(appId: string): Promise<{ message: string }> {
    try {
      const response = await apiClient.post(`/api/v1/cloud/apps/${appId}/block`);
      return response.data;
    } catch (error) {
      console.error('Error blocking cloud app:', error);
      throw error;
    }
  }

  async allowCloudApp(appId: string): Promise<{ message: string }> {
    try {
      const response = await apiClient.post(`/api/v1/cloud/apps/${appId}/allow`);
      return response.data;
    } catch (error) {
      console.error('Error allowing cloud app:', error);
      throw error;
    }
  }

  // CSPM Provider Data
  async getCSPMProviderData(provider: string): Promise<{
    name: string;
    status: string;
    last_sync: string;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
  }> {
    try {
      const response = await apiClient.get(`/api/v1/cloud/cspm/provider/${provider}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching CSPM provider data:', error);
      throw error;
    }
  }

  async syncCSPMProvider(provider: string): Promise<{ message: string }> {
    try {
      const response = await apiClient.post(`/api/v1/cloud/cspm/provider/${provider}/sync`);
      return response.data;
    } catch (error) {
      console.error('Error syncing CSPM provider:', error);
      throw error;
    }
  }

  // Security Findings
  async getSecurityFindings(): Promise<{
    id: string;
    title: string;
    description: string;
    severity: string;
    provider: string;
    resource_id: string;
    resource_type: string;
    region: string;
    status: string;
    created_at: string;
    updated_at: string;
    remediation_steps: string;
  }[]> {
    try {
      const response = await apiClient.get('/api/v1/cloud/security-findings');
      return response.data;
    } catch (error) {
      console.error('Error fetching security findings:', error);
      throw error;
    }
  }
}

export const cloudSecurityService = new CloudSecurityService();
export default cloudSecurityService;
