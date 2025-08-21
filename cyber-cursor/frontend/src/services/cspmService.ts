import { apiClient } from '../utils/apiClient';

// Types
export interface DashboardSummary {
  total_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  compliance_score: number;
  last_sync?: string;
}

export interface RiskHeatmapItem {
  asset_id: string;
  asset_name: string;
  resource_type: string;
  risk_score: number;
  findings_count: number;
  critical_findings: number;
}

export interface FindingSummary {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  asset_name: string;
  resource_type: string;
  created_at: string;
  status: string;
}

export interface Connector {
  id: string;
  name: string;
  type: 'aws' | 'azure' | 'gcp' | 'oci' | 'kubernetes';
  status: 'pending' | 'connecting' | 'connected' | 'disconnected' | 'error' | 'syncing';
  last_synced?: string;
  project_id: string;
  config: Record<string, any>;
  sync_interval: number;
}

export interface Asset {
  id: string;
  name?: string;
  resource_type: string;
  cloud?: string;
  region?: string;
  risk_score: number;
  tags?: Record<string, any>;
  last_seen: string;
  metadata?: Record<string, any>;
}

export interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  asset_name: string;
  resource_type: string;
  created_at: string;
  description?: string;
  evidence?: Record<string, any>;
  risk_score?: number;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  framework: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  enabled: boolean;
  category?: string;
  rule: Record<string, any>;
}

export interface Organization {
  id: string;
  name: string;
  description?: string;
  settings?: Record<string, any>;
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  org_id: string;
  settings?: Record<string, any>;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface ConnectorCreateRequest {
  name: string;
  type: 'aws' | 'azure' | 'gcp' | 'oci' | 'kubernetes';
  config: Record<string, any>;
  project_id: string;
  sync_interval?: number;
}

export interface ConnectorSyncRequest {
  force?: boolean;
  regions?: string[];
}

export interface ConnectorSyncResponse {
  job_id: string;
  status: string;
  message: string;
}

export interface FindingUpdateRequest {
  status?: 'open' | 'acknowledged' | 'in_progress' | 'resolved' | 'suppressed';
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title?: string;
  description?: string;
  owner_id?: string;
  comments?: string[];
  remediation_notes?: string;
}

export interface BulkFindingUpdateRequest {
  finding_ids: string[];
  status?: 'open' | 'acknowledged' | 'in_progress' | 'resolved' | 'suppressed';
  owner_id?: string;
  comments?: string;
}

export interface PolicyCreateRequest {
  name: string;
  description?: string;
  framework: string;
  rule: Record<string, any>;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category?: string;
  compliance_standards?: string[];
  remediation_steps?: string;
  auto_remediable?: boolean;
}

export interface PolicyUpdateRequest {
  name?: string;
  description?: string;
  rule?: Record<string, any>;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category?: string;
  compliance_standards?: string[];
  remediation_steps?: string;
  auto_remediable?: boolean;
  enabled?: boolean;
}

export interface PolicyEvaluationRequest {
  asset_id?: string;
  policy_id?: string;
  dry_run?: boolean;
}

export interface PolicyEvaluationResponse {
  job_id: string;
  status: string;
  message: string;
}

export interface AssetSearchParams {
  cloud?: 'aws' | 'azure' | 'gcp' | 'oci' | 'kubernetes';
  type?: string;
  region?: string;
  project_id?: string;
  risk_score_min?: number;
  risk_score_max?: number;
  page?: number;
  per_page?: number;
}

export interface FindingSearchParams {
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status?: 'open' | 'acknowledged' | 'in_progress' | 'resolved' | 'suppressed';
  asset_id?: string;
  policy_id?: string;
  created_after?: string;
  created_before?: string;
  page?: number;
  per_page?: number;
}

class CSPMService {
  private baseUrl = '/api/v1/cspm';

  // Dashboard
  async getDashboardSummary(projectId?: string): Promise<{
    summary: DashboardSummary;
    latest_findings: FindingSummary[];
    risk_heatmap: {
      items: RiskHeatmapItem[];
      total_assets: number;
      high_risk_assets: number;
    };
    top_misconfigs: Array<{
      policy_name: string;
      category: string;
      count: number;
    }>;
  }> {
    const params = projectId ? `?project_id=${projectId}` : '';
    const response = await apiClient.get(`${this.baseUrl}/dashboard/summary${params}`);
    return response.data;
  }

  async getRiskHeatmap(projectId?: string, limit: number = 50): Promise<{
    items: RiskHeatmapItem[];
    total_assets: number;
    high_risk_assets: number;
  }> {
    const params = new URLSearchParams();
    if (projectId) params.append('project_id', projectId);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/dashboard/heatmap?${params}`);
    return response.data;
  }

  // Organizations & Projects
  async getOrganizations(): Promise<Organization[]> {
    const response = await apiClient.get(`${this.baseUrl}/organizations`);
    return response.data;
  }

  async createOrganization(organization: Omit<Organization, 'id' | 'created_at'>): Promise<Organization> {
    const response = await apiClient.post(`${this.baseUrl}/organizations`, organization);
    return response.data;
  }

  async getProjects(orgId?: string): Promise<Project[]> {
    const params = orgId ? `?org_id=${orgId}` : '';
    const response = await apiClient.get(`${this.baseUrl}/projects${params}`);
    return response.data;
  }

  async createProject(project: Omit<Project, 'id' | 'created_at'>): Promise<Project> {
    const response = await apiClient.post(`${this.baseUrl}/projects`, project);
    return response.data;
  }

  // Connectors
  async getConnectors(params?: {
    project_id?: string;
    type?: 'aws' | 'azure' | 'gcp' | 'oci' | 'kubernetes';
    status?: 'pending' | 'connecting' | 'connected' | 'disconnected' | 'error' | 'syncing';
  }): Promise<Connector[]> {
    const queryParams = new URLSearchParams();
    if (params?.project_id) queryParams.append('project_id', params.project_id);
    if (params?.type) queryParams.append('type', params.type);
    if (params?.status) queryParams.append('status', params.status);
    
    const response = await apiClient.get(`${this.baseUrl}/connectors?${queryParams}`);
    return response.data;
  }

  async getConnector(connectorId: string): Promise<Connector> {
    const response = await apiClient.get(`${this.baseUrl}/connectors/${connectorId}`);
    return response.data;
  }

  async createConnector(connector: ConnectorCreateRequest): Promise<Connector> {
    const response = await apiClient.post(`${this.baseUrl}/connectors`, connector);
    return response.data;
  }

  async syncConnector(connectorId: string, syncRequest: ConnectorSyncRequest): Promise<ConnectorSyncResponse> {
    const response = await apiClient.post(`${this.baseUrl}/connectors/${connectorId}/sync`, syncRequest);
    return response.data;
  }

  // Assets
  async getAssets(params?: AssetSearchParams): Promise<PaginatedResponse<Asset>> {
    const queryParams = new URLSearchParams();
    if (params?.cloud) queryParams.append('cloud', params.cloud);
    if (params?.type) queryParams.append('type', params.type);
    if (params?.region) queryParams.append('region', params.region);
    if (params?.risk_score_min !== undefined) queryParams.append('risk_score_min', params.risk_score_min.toString());
    if (params?.risk_score_max !== undefined) queryParams.append('risk_score_max', params.risk_score_max.toString());
    if (params?.page) queryParams.append('page', params.page.toString());
    if (params?.per_page) queryParams.append('per_page', params.per_page.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/assets?${queryParams}`);
    return response.data;
  }

  async getAsset(assetId: string): Promise<Asset> {
    const response = await apiClient.get(`${this.baseUrl}/assets/${assetId}`);
    return response.data;
  }

  // Findings
  async getFindings(params?: FindingSearchParams): Promise<PaginatedResponse<Finding>> {
    const queryParams = new URLSearchParams();
    if (params?.severity) queryParams.append('severity', params.severity);
    if (params?.status) queryParams.append('status', params.status);
    if (params?.asset_id) queryParams.append('asset_id', params.asset_id);
    if (params?.policy_id) queryParams.append('policy_id', params.policy_id);
    if (params?.created_after) queryParams.append('created_after', params.created_after);
    if (params?.created_before) queryParams.append('created_before', params.created_before);
    if (params?.page) queryParams.append('page', params.page.toString());
    if (params?.per_page) queryParams.append('per_page', params.per_page.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/findings?${queryParams}`);
    return response.data;
  }

  async getFinding(findingId: string): Promise<Finding> {
    const response = await apiClient.get(`${this.baseUrl}/findings/${findingId}`);
    return response.data;
  }

  async updateFinding(findingId: string, update: FindingUpdateRequest): Promise<Finding> {
    const response = await apiClient.patch(`${this.baseUrl}/findings/${findingId}`, update);
    return response.data;
  }

  async bulkUpdateFindings(update: BulkFindingUpdateRequest): Promise<{
    updated_count: number;
    failed_count: number;
    failed_ids: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/findings/bulk`, update);
    return response.data;
  }

  // Policies
  async getPolicies(params?: {
    framework?: string;
    enabled?: boolean;
  }): Promise<Policy[]> {
    const queryParams = new URLSearchParams();
    if (params?.framework) queryParams.append('framework', params.framework);
    if (params?.enabled !== undefined) queryParams.append('enabled', params.enabled.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/policies?${queryParams}`);
    return response.data;
  }

  async createPolicy(policy: PolicyCreateRequest): Promise<Policy> {
    const response = await apiClient.post(`${this.baseUrl}/policies`, policy);
    return response.data;
  }

  async updatePolicy(policyId: string, update: PolicyUpdateRequest): Promise<Policy> {
    const response = await apiClient.patch(`${this.baseUrl}/policies/${policyId}`, update);
    return response.data;
  }

  async evaluatePolicies(evaluationRequest: PolicyEvaluationRequest): Promise<PolicyEvaluationResponse> {
    const response = await apiClient.post(`${this.baseUrl}/policies/evaluate`, evaluationRequest);
    return response.data;
  }

  // Jobs
  async getJobs(params?: {
    status?: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
    type?: 'sync' | 'scan' | 'policy_evaluation' | 'remediation';
    connector_id?: string;
  }): Promise<Array<{
    id: string;
    type: string;
    status: string;
    progress: number;
    created_at: string;
    started_at?: string;
    completed_at?: string;
  }>> {
    const queryParams = new URLSearchParams();
    if (params?.status) queryParams.append('status', params.status);
    if (params?.type) queryParams.append('type', params.type);
    if (params?.connector_id) queryParams.append('connector_id', params.connector_id);
    
    const response = await apiClient.get(`${this.baseUrl}/jobs?${queryParams}`);
    return response.data;
  }

  async getJob(jobId: string): Promise<{
    id: string;
    type: string;
    status: string;
    progress: number;
    created_at: string;
    started_at?: string;
    completed_at?: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/jobs/${jobId}`);
    return response.data;
  }

  // Integrations
  async createIntegration(integration: {
    name: string;
    type: string;
    config: Record<string, any>;
    project_id: string;
    enabled?: boolean;
  }): Promise<{
    id: string;
    name: string;
    type: string;
    config: Record<string, any>;
    project_id: string;
    enabled: boolean;
    created_at: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/integrations`, integration);
    return response.data;
  }

  async testIntegration(integrationId: string): Promise<{
    message: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/integrations/${integrationId}/test`);
    return response.data;
  }

  // Compliance
  async getComplianceFrameworks(): Promise<Array<{
    id: string;
    name: string;
    version?: string;
    description?: string;
    created_at: string;
  }>> {
    const response = await apiClient.get(`${this.baseUrl}/compliance/frameworks`);
    return response.data;
  }

  async generateComplianceReport(reportRequest: {
    project_id: string;
    framework_id: string;
    score?: number;
    total_controls?: number;
    passed_controls?: number;
    failed_controls?: number;
  }): Promise<{
    id: string;
    project_id: string;
    framework_id: string;
    score: number;
    total_controls: number;
    passed_controls: number;
    failed_controls: number;
    generated_at: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/compliance/reports`, reportRequest);
    return response.data;
  }

  // Utility methods
  async refreshData(projectId?: string): Promise<void> {
    // Refresh all data for a project
    await Promise.all([
      this.getDashboardSummary(projectId),
      this.getConnectors({ project_id: projectId }),
      this.getAssets({ project_id: projectId }),
      this.getFindings({ page: 1, per_page: 50 }),
      this.getPolicies()
    ]);
  }

  // Risk scoring utilities
  getRiskLevel(riskScore: number): 'critical' | 'high' | 'medium' | 'low' | 'minimal' {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    if (riskScore >= 20) return 'low';
    return 'minimal';
  }

  getRiskColor(riskScore: number): string {
    const level = this.getRiskLevel(riskScore);
    switch (level) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800';
      case 'minimal':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  }

  getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800';
      case 'info':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  }

  getStatusColor(status: string): string {
    switch (status) {
      case 'connected':
        return 'bg-green-100 text-green-800';
      case 'connecting':
      case 'syncing':
        return 'bg-blue-100 text-blue-800';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      case 'disconnected':
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  }
}

// Enhanced CSPM Service Methods

// Asset Relationships
export const createAssetRelationship = async (
  assetId: string,
  relationship: {
    child_asset_id: string;
    relationship_type: string;
    metadata?: Record<string, any>;
  }
): Promise<any> => {
  const response = await apiClient.post(`/api/v1/cspm/assets/${assetId}/relationships`, relationship);
  return response.data;
};

export const getAssetRelationships = async (assetId: string): Promise<any[]> => {
  const response = await apiClient.get(`/api/v1/cspm/assets/${assetId}/relationships`);
  return response.data;
};

// Policy Evaluation
export const evaluatePolicyOnAsset = async (
  policyId: string,
  assetId: string
): Promise<any> => {
  const response = await apiClient.post(`/api/v1/cspm/policies/${policyId}/evaluate?asset_id=${assetId}`);
  return response.data;
};

export const getPolicyEvaluationResults = async (
  policyId: string,
  limit: number = 100
): Promise<any[]> => {
  const response = await apiClient.get(`/api/v1/cspm/policies/${policyId}/evaluation-results?limit=${limit}`);
  return response.data;
};

// Compliance Controls
export const createComplianceControl = async (control: {
  framework_id: string;
  control_id: string;
  title: string;
  description?: string;
  category?: string;
  requirements?: Record<string, any>[];
  policy_mappings?: string[];
}): Promise<any> => {
  const response = await apiClient.post('/api/v1/cspm/compliance/controls', control);
  return response.data;
};

export const getFrameworkControls = async (frameworkId: string): Promise<any[]> => {
  const response = await apiClient.get(`/api/v1/cspm/compliance/frameworks/${frameworkId}/controls`);
  return response.data;
};

export const createComplianceMapping = async (mapping: {
  control_id: string;
  policy_id: string;
  mapping_type?: string;
  confidence_score?: number;
  notes?: string;
}): Promise<any> => {
  const response = await apiClient.post('/api/v1/cspm/compliance/mappings', mapping);
  return response.data;
};

// Scan Templates
export const createScanTemplate = async (template: {
  project_id: string;
  name: string;
  description?: string;
  scan_config: Record<string, any>;
  schedule?: string;
  enabled?: boolean;
}): Promise<any> => {
  const response = await apiClient.post('/api/v1/cspm/scan-templates', template);
  return response.data;
};

export const getScanTemplates = async (projectId?: string): Promise<any[]> => {
  const params = projectId ? `?project_id=${projectId}` : '';
  const response = await apiClient.get(`/api/v1/cspm/scan-templates${params}`);
  return response.data;
};

export const updateScanTemplate = async (
  templateId: string,
  updates: {
    name?: string;
    description?: string;
    scan_config?: Record<string, any>;
    schedule?: string;
    enabled?: boolean;
  }
): Promise<any> => {
  const response = await apiClient.put(`/api/v1/cspm/scan-templates/${templateId}`, updates);
  return response.data;
};

// Remediation Playbooks
export const createRemediationPlaybook = async (playbook: {
  name: string;
  description?: string;
  category?: string;
  steps: Record<string, any>[];
  prerequisites?: Record<string, any>[];
  estimated_time?: number;
  risk_level?: string;
  auto_approval?: boolean;
}): Promise<any> => {
  const response = await apiClient.post('/api/v1/cspm/remediation/playbooks', playbook);
  return response.data;
};

export const getRemediationPlaybooks = async (category?: string): Promise<any[]> => {
  const params = category ? `?category=${category}` : '';
  const response = await apiClient.get(`/api/v1/cspm/remediation/playbooks${params}`);
  return response.data;
};

export const executeRemediationPlaybook = async (
  playbookId: string,
  findingId: string
): Promise<any> => {
  const response = await apiClient.post(`/api/v1/cspm/remediation/playbooks/${playbookId}/execute?finding_id=${findingId}`);
  return response.data;
};

// Risk Assessment
export const createRiskAssessment = async (
  assetId: string,
  assessment: {
    overall_score: number;
    factors?: Record<string, any>;
    recommendations?: Record<string, any>[];
  }
): Promise<any> => {
  const response = await apiClient.post(`/api/v1/cspm/assets/${assetId}/risk-assessment`, assessment);
  return response.data;
};

export const getAssetRiskAssessments = async (
  assetId: string,
  limit: number = 50
): Promise<any[]> => {
  const response = await apiClient.get(`/api/v1/cspm/assets/${assetId}/risk-assessments?limit=${limit}`);
  return response.data;
};

// Integration Webhooks
export const createIntegrationWebhook = async (
  integrationId: string,
  webhook: {
    webhook_url: string;
    secret_key?: string;
    events?: string[];
    enabled?: boolean;
  }
): Promise<any> => {
  const response = await apiClient.post(`/api/v1/cspm/integrations/${integrationId}/webhooks`, webhook);
  return response.data;
};

export const testWebhook = async (
  integrationId: string,
  webhookId: string
): Promise<any> => {
  const response = await apiClient.post(`/api/v1/cspm/integrations/${integrationId}/webhooks/${webhookId}/test`);
  return response.data;
};

// Enhanced Asset Management
export const getAssetDetails = async (assetId: string): Promise<any> => {
  const response = await apiClient.get(`/api/v1/cspm/assets/${assetId}`);
  return response.data;
};

export const updateAssetTags = async (
  assetId: string,
  tags: Record<string, any>
): Promise<any> => {
  const response = await apiClient.patch(`/api/v1/cspm/assets/${assetId}`, { tags });
  return response.data;
};

// Enhanced Policy Management
export const getPolicyDetails = async (policyId: string): Promise<any> => {
  const response = await apiClient.get(`/api/v1/cspm/policies/${policyId}`);
  return response.data;
};

export const updatePolicy = async (
  policyId: string,
  updates: {
    name?: string;
    description?: string;
    rule?: Record<string, any>;
    enabled?: boolean;
    severity?: string;
    category?: string;
  }
): Promise<any> => {
  const response = await apiClient.patch(`/api/v1/cspm/policies/${policyId}`, updates);
  return response.data;
};

// Bulk Operations
export const bulkUpdateFindings = async (
  findingIds: string[],
  updates: {
    status?: string;
    owner_id?: string;
    comments?: string;
  }
): Promise<any> => {
  const response = await apiClient.post('/api/v1/cspm/findings/bulk', {
    finding_ids: findingIds,
    updates
  });
  return response.data;
};

export const bulkExecuteRemediation = async (
  findingIds: string[],
  playbookId: string
): Promise<any[]> => {
  const promises = findingIds.map(findingId => 
    executeRemediationPlaybook(playbookId, findingId)
  );
  return Promise.all(promises);
};

// Advanced Search and Filtering
export const searchAssets = async (params: {
  query?: string;
  cloud?: string;
  resource_type?: string;
  tags?: Record<string, any>;
  risk_score_min?: number;
  risk_score_max?: number;
  page?: number;
  per_page?: number;
}): Promise<{ items: any[]; total: number }> => {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      if (typeof value === 'object') {
        searchParams.append(key, JSON.stringify(value));
      } else {
        searchParams.append(key, String(value));
      }
    }
  });
  
  const response = await apiClient.get(`/api/v1/cspm/assets/search?${searchParams.toString()}`);
  return response.data;
};

export const searchFindings = async (params: {
  query?: string;
  severity?: string[];
  status?: string[];
  asset_type?: string[];
  policy_framework?: string[];
  created_after?: string;
  created_before?: string;
  page?: number;
  per_page?: number;
}): Promise<{ items: any[]; total: number }> => {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      if (Array.isArray(value)) {
        value.forEach(v => searchParams.append(key, v));
      } else {
        searchParams.append(key, String(value));
      }
    }
  });
  
  const response = await apiClient.get(`/api/v1/cspm/findings/search?${searchParams.toString()}`);
  return response.data;
};

export const cspmService = new CSPMService();
export default cspmService;
