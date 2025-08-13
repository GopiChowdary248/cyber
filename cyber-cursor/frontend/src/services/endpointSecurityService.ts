import { apiClient } from '../utils/apiClient';

export interface Endpoint {
  id: string;
  hostname: string;
  ip_address: string;
  mac_address: string;
  os_type: string;
  os_version: string;
  status: 'online' | 'offline' | 'quarantined' | 'compromised';
  last_seen: string;
  security_status: 'secure' | 'at_risk' | 'compromised';
  compliance_score: number;
  vulnerabilities_count: number;
  malware_detected: boolean;
  user_id?: string;
  department?: string;
  location?: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface EndpointVulnerability {
  id: string;
  endpoint_id: string;
  cve_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  cvss_score: number;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  discovered_at: string;
  last_updated: string;
  remediation_steps: string[];
  affected_software: string[];
  references: string[];
}

export interface EndpointThreat {
  id: string;
  endpoint_id: string;
  threat_type: 'malware' | 'ransomware' | 'trojan' | 'spyware' | 'other';
  threat_name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'detected' | 'contained' | 'removed' | 'false_positive';
  detected_at: string;
  last_updated: string;
  file_path?: string;
  file_hash?: string;
  process_name?: string;
  network_connections: string[];
  indicators: string[];
  remediation_status: 'pending' | 'in_progress' | 'completed';
}

export interface EndpointPolicy {
  id: string;
  name: string;
  description: string;
  policy_type: 'access_control' | 'application_control' | 'network_control' | 'data_protection';
  rules: PolicyRule[];
  is_active: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
  applied_endpoints: string[];
}

export interface PolicyRule {
  id: string;
  rule_type: string;
  conditions: Record<string, any>;
  actions: string[];
  priority: number;
  is_enabled: boolean;
}

export interface EndpointCompliance {
  endpoint_id: string;
  compliance_framework: string;
  overall_score: number;
  categories: ComplianceCategory[];
  last_assessment: string;
  next_assessment: string;
  status: 'compliant' | 'non_compliant' | 'partially_compliant';
}

export interface ComplianceCategory {
  name: string;
  score: number;
  status: 'compliant' | 'non_compliant' | 'partially_compliant';
  requirements: ComplianceRequirement[];
}

export interface ComplianceRequirement {
  id: string;
  title: string;
  description: string;
  status: 'compliant' | 'non_compliant' | 'not_applicable';
  evidence: string[];
  remediation_notes?: string;
}

export interface EndpointActivity {
  id: string;
  endpoint_id: string;
  activity_type: 'login' | 'logout' | 'file_access' | 'network_connection' | 'process_start' | 'registry_change';
  timestamp: string;
  user_id?: string;
  details: Record<string, any>;
  risk_score: number;
  flagged: boolean;
}

export interface EndpointQuarantine {
  endpoint_id: string;
  quarantined_at: string;
  reason: string;
  quarantined_by: string;
  status: 'quarantined' | 'released' | 'pending_review';
  notes?: string;
  released_at?: string;
  released_by?: string;
}

class EndpointSecurityService {
  private baseUrl = '/api/v1/endpoint-security';

  // Endpoint Management
  async getEndpoints(
    status?: string,
    securityStatus?: string,
    department?: string,
    limit: number = 100
  ): Promise<Endpoint[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (securityStatus) params.append('security_status', securityStatus);
    if (department) params.append('department', department);
    if (limit) params.append('limit', limit.toString());

    const response = await apiClient.get(`${this.baseUrl}/endpoints?${params}`);
    return response.data;
  }

  async getEndpoint(endpointId: string): Promise<Endpoint> {
    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}`);
    return response.data;
  }

  async createEndpoint(endpointData: Omit<Endpoint, 'id'>): Promise<{
    message: string;
    endpoint_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints`, endpointData);
    return response.data;
  }

  async updateEndpoint(endpointId: string, updateData: Partial<Endpoint>): Promise<{
    message: string;
    endpoint_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/endpoints/${endpointId}`, updateData);
    return response.data;
  }

  async deleteEndpoint(endpointId: string): Promise<{
    message: string;
    endpoint_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/endpoints/${endpointId}`);
    return response.data;
  }

  // Vulnerability Management
  async getEndpointVulnerabilities(endpointId: string, severity?: string, status?: string): Promise<EndpointVulnerability[]> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);

    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}/vulnerabilities?${params}`);
    return response.data;
  }

  async updateVulnerabilityStatus(
    endpointId: string,
    vulnerabilityId: string,
    status: string,
    notes?: string
  ): Promise<{
    message: string;
    vulnerability_id: string;
    status: string;
  }> {
    const response = await apiClient.put(
      `${this.baseUrl}/endpoints/${endpointId}/vulnerabilities/${vulnerabilityId}`,
      { status, notes }
    );
    return response.data;
  }

  // Threat Management
  async getEndpointThreats(endpointId: string, threatType?: string, status?: string): Promise<EndpointThreat[]> {
    const params = new URLSearchParams();
    if (threatType) params.append('threat_type', threatType);
    if (status) params.append('status', status);

    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}/threats?${params}`);
    return response.data;
  }

  async updateThreatStatus(
    endpointId: string,
    threatId: string,
    status: string,
    remediationNotes?: string
  ): Promise<{
    message: string;
    threat_id: string;
    status: string;
  }> {
    const response = await apiClient.put(
      `${this.baseUrl}/endpoints/${endpointId}/threats/${threatId}`,
      { status, remediation_notes: remediationNotes }
    );
    return response.data;
  }

  // Policy Management
  async getEndpointPolicies(policyType?: string, isActive?: boolean): Promise<EndpointPolicy[]> {
    const params = new URLSearchParams();
    if (policyType) params.append('policy_type', policyType);
    if (isActive !== undefined) params.append('is_active', isActive.toString());

    const response = await apiClient.get(`${this.baseUrl}/policies?${params}`);
    return response.data;
  }

  async createEndpointPolicy(policyData: Omit<EndpointPolicy, 'id' | 'created_at' | 'updated_at'>): Promise<{
    message: string;
    policy_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/policies`, policyData);
    return response.data;
  }

  async updateEndpointPolicy(policyId: string, updateData: Partial<EndpointPolicy>): Promise<{
    message: string;
    policy_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/policies/${policyId}`, updateData);
    return response.data;
  }

  async deleteEndpointPolicy(policyId: string): Promise<{
    message: string;
    policy_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/policies/${policyId}`);
    return response.data;
  }

  // Compliance Management
  async getEndpointCompliance(endpointId: string, framework?: string): Promise<EndpointCompliance[]> {
    const params = new URLSearchParams();
    if (framework) params.append('framework', framework);

    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}/compliance?${params}`);
    return response.data;
  }

  async runComplianceAssessment(endpointId: string, framework: string): Promise<{
    message: string;
    assessment_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints/${endpointId}/compliance/assess`, {
      framework
    });
    return response.data;
  }

  // Activity Monitoring
  async getEndpointActivity(
    endpointId: string,
    activityType?: string,
    startTime?: string,
    endTime?: string,
    limit: number = 100
  ): Promise<EndpointActivity[]> {
    const params = new URLSearchParams();
    if (activityType) params.append('activity_type', activityType);
    if (startTime) params.append('start_time', startTime);
    if (endTime) params.append('end_time', endTime);
    if (limit) params.append('limit', limit.toString());

    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}/activity?${params}`);
    return response.data;
  }

  // Quarantine Management
  async quarantineEndpoint(
    endpointId: string,
    reason: string,
    quarantinedBy: string
  ): Promise<{
    message: string;
    endpoint_id: string;
    quarantine_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints/${endpointId}/quarantine`, {
      reason,
      quarantined_by: quarantinedBy
    });
    return response.data;
  }

  async releaseEndpoint(
    endpointId: string,
    releasedBy: string,
    notes?: string
  ): Promise<{
    message: string;
    endpoint_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints/${endpointId}/release`, {
      released_by: releasedBy,
      notes
    });
    return response.data;
  }

  async getQuarantinedEndpoints(): Promise<EndpointQuarantine[]> {
    const response = await apiClient.get(`${this.baseUrl}/quarantine`);
    return response.data;
  }

  // Bulk Operations
  async bulkUpdateEndpointStatus(
    endpointIds: string[],
    status: string,
    notes?: string
  ): Promise<{
    message: string;
    updated_count: number;
    failed_count: number;
    failed_endpoints: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints/bulk-update`, {
      endpoint_ids: endpointIds,
      status,
      notes
    });
    return response.data;
  }

  async bulkQuarantineEndpoints(
    endpointIds: string[],
    reason: string,
    quarantinedBy: string
  ): Promise<{
    message: string;
    quarantined_count: number;
    failed_count: number;
    failed_endpoints: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints/bulk-quarantine`, {
      endpoint_ids: endpointIds,
      reason,
      quarantined_by: quarantinedBy
    });
    return response.data;
  }

  // Analytics and Reporting
  async getEndpointSecuritySummary(): Promise<{
    total_endpoints: number;
    online_endpoints: number;
    offline_endpoints: number;
    quarantined_endpoints: number;
    compromised_endpoints: number;
    average_compliance_score: number;
    total_vulnerabilities: number;
    total_threats: number;
    risk_distribution: Record<string, number>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/summary`);
    return response.data;
  }

  async getEndpointRiskAssessment(endpointId: string): Promise<{
    endpoint_id: string;
    risk_score: number;
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    factors: string[];
    recommendations: string[];
    last_assessment: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}/risk-assessment`);
    return response.data;
  }
}

export const endpointSecurityService = new EndpointSecurityService();
export default endpointSecurityService;
