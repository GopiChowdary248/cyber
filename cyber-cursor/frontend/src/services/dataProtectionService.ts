import { apiClient } from '../utils/apiClient';

export interface DataClassification {
  id: string;
  name: string;
  description: string;
  sensitivity_level: 'public' | 'internal' | 'confidential' | 'restricted';
  data_types: string[];
  retention_period: number; // in days
  encryption_required: boolean;
  access_controls: string[];
  created_at: string;
  updated_at: string;
}

export interface DataAsset {
  id: string;
  name: string;
  description: string;
  classification_id: string;
  location: string;
  format: string;
  size: number;
  owner_id: number;
  created_at: string;
  updated_at: string;
  last_accessed: string;
  tags: string[];
  metadata: any;
}

export interface DataAccessLog {
  id: string;
  asset_id: string;
  user_id: number;
  access_type: 'read' | 'write' | 'delete' | 'export';
  timestamp: string;
  ip_address: string;
  user_agent: string;
  success: boolean;
  reason?: string;
  data_accessed?: string;
}

export interface DataBreach {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  data_assets_affected: string[];
  affected_records: number;
  breach_type: string;
  discovery_date: string;
  containment_date?: string;
  resolution_date?: string;
  status: 'investigating' | 'contained' | 'resolved' | 'closed';
  reported_by: number;
  assigned_to?: number;
  remediation_actions: string[];
  regulatory_impact: string[];
  created_at: string;
  updated_at: string;
}

export interface DataRetentionPolicy {
  id: string;
  name: string;
  description: string;
  data_types: string[];
  retention_period: number; // in days
  retention_action: 'delete' | 'archive' | 'anonymize';
  exceptions: string[];
  review_frequency: number; // in days
  last_review: string;
  next_review: string;
  created_at: string;
  updated_at: string;
}

export interface DataProtectionMetrics {
  total_data_assets: number;
  classified_assets: number;
  encrypted_assets: number;
  access_logs_today: number;
  active_breaches: number;
  compliance_score: number;
  data_volume: number;
  top_data_types: string[];
}

class DataProtectionService {
  // Get data classifications
  async getDataClassifications(): Promise<DataClassification[]> {
    const response = await apiClient.get('/data-protection/classifications');
    return response.data;
  }

  // Get data classification by ID
  async getDataClassification(classificationId: string): Promise<DataClassification> {
    const response = await apiClient.get(`/data-protection/classifications/${classificationId}`);
    return response.data;
  }

  // Create data classification
  async createDataClassification(classificationData: Partial<DataClassification>): Promise<DataClassification> {
    const response = await apiClient.post('/data-protection/classifications', classificationData);
    return response.data;
  }

  // Update data classification
  async updateDataClassification(
    classificationId: string,
    updateData: Partial<DataClassification>
  ): Promise<DataClassification> {
    const response = await apiClient.put(`/data-protection/classifications/${classificationId}`, updateData);
    return response.data;
  }

  // Delete data classification
  async deleteDataClassification(classificationId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/data-protection/classifications/${classificationId}`);
    return response.data;
  }

  // Get data assets
  async getDataAssets(
    skip: number = 0,
    limit: number = 100,
    classification_id?: string,
    owner_id?: number,
    location?: string
  ): Promise<{ assets: DataAsset[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (classification_id) params.append('classification_id', classification_id);
    if (owner_id) params.append('owner_id', owner_id.toString());
    if (location) params.append('location', location);

    const response = await apiClient.get(`/data-protection/assets?${params.toString()}`);
    return response.data;
  }

  // Get data asset by ID
  async getDataAsset(assetId: string): Promise<DataAsset> {
    const response = await apiClient.get(`/data-protection/assets/${assetId}`);
    return response.data;
  }

  // Create data asset
  async createDataAsset(assetData: Partial<DataAsset>): Promise<DataAsset> {
    const response = await apiClient.post('/data-protection/assets', assetData);
    return response.data;
  }

  // Update data asset
  async updateDataAsset(assetId: string, updateData: Partial<DataAsset>): Promise<DataAsset> {
    const response = await apiClient.put(`/data-protection/assets/${assetId}`, updateData);
    return response.data;
  }

  // Delete data asset
  async deleteDataAsset(assetId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/data-protection/assets/${assetId}`);
    return response.data;
  }

  // Get data access logs
  async getDataAccessLogs(
    skip: number = 0,
    limit: number = 100,
    asset_id?: string,
    user_id?: number,
    access_type?: string,
    date_from?: string,
    date_to?: string
  ): Promise<{ logs: DataAccessLog[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (asset_id) params.append('asset_id', asset_id);
    if (user_id) params.append('user_id', user_id.toString());
    if (access_type) params.append('access_type', access_type);
    if (date_from) params.append('date_from', date_from);
    if (date_to) params.append('date_to', date_to);

    const response = await apiClient.get(`/data-protection/access-logs?${params.toString()}`);
    return response.data;
  }

  // Log data access
  async logDataAccess(accessData: Partial<DataAccessLog>): Promise<DataAccessLog> {
    const response = await apiClient.post('/data-protection/access-logs', accessData);
    return response.data;
  }

  // Get data breaches
  async getDataBreaches(
    skip: number = 0,
    limit: number = 100,
    status?: string,
    severity?: string,
    assigned_to?: number
  ): Promise<{ breaches: DataBreach[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (assigned_to) params.append('assigned_to', assigned_to.toString());

    const response = await apiClient.get(`/data-protection/breaches?${params.toString()}`);
    return response.data;
  }

  // Get data breach by ID
  async getDataBreach(breachId: string): Promise<DataBreach> {
    const response = await apiClient.get(`/data-protection/breaches/${breachId}`);
    return response.data;
  }

  // Create data breach
  async createDataBreach(breachData: Partial<DataBreach>): Promise<DataBreach> {
    const response = await apiClient.post('/data-protection/breaches', breachData);
    return response.data;
  }

  // Update data breach
  async updateDataBreach(breachId: string, updateData: Partial<DataBreach>): Promise<DataBreach> {
    const response = await apiClient.put(`/data-protection/breaches/${breachId}`, updateData);
    return response.data;
  }

  // Delete data breach
  async deleteDataBreach(breachId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/data-protection/breaches/${breachId}`);
    return response.data;
  }

  // Get data retention policies
  async getDataRetentionPolicies(): Promise<DataRetentionPolicy[]> {
    const response = await apiClient.get('/data-protection/retention-policies');
    return response.data;
  }

  // Get data retention policy by ID
  async getDataRetentionPolicy(policyId: string): Promise<DataRetentionPolicy> {
    const response = await apiClient.get(`/data-protection/retention-policies/${policyId}`);
    return response.data;
  }

  // Create data retention policy
  async createDataRetentionPolicy(policyData: Partial<DataRetentionPolicy>): Promise<DataRetentionPolicy> {
    const response = await apiClient.post('/data-protection/retention-policies', policyData);
    return response.data;
  }

  // Update data retention policy
  async updateDataRetentionPolicy(
    policyId: string,
    updateData: Partial<DataRetentionPolicy>
  ): Promise<DataRetentionPolicy> {
    const response = await apiClient.put(`/data-protection/retention-policies/${policyId}`, updateData);
    return response.data;
  }

  // Delete data retention policy
  async deleteDataRetentionPolicy(policyId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/data-protection/retention-policies/${policyId}`);
    return response.data;
  }

  // Get data protection metrics
  async getDataProtectionMetrics(): Promise<DataProtectionMetrics> {
    const response = await apiClient.get('/data-protection/metrics');
    return response.data;
  }

  // Scan data for sensitive information
  async scanDataForSensitiveInfo(data: any): Promise<{ sensitive_data: any[]; risk_score: number }> {
    const response = await apiClient.post('/data-protection/scan-sensitive', data);
    return response.data;
  }

  // Encrypt data asset
  async encryptDataAsset(assetId: string, encryptionKey?: string): Promise<{ message: string; encrypted: boolean }> {
    const response = await apiClient.post(`/data-protection/assets/${assetId}/encrypt`, { encryption_key: encryptionKey });
    return response.data;
  }

  // Decrypt data asset
  async decryptDataAsset(assetId: string, decryptionKey?: string): Promise<{ message: string; decrypted: boolean }> {
    const response = await apiClient.post(`/data-protection/assets/${assetId}/decrypt`, { decryption_key: decryptionKey });
    return response.data;
  }

  // Export data protection report
  async exportDataProtectionReport(
    reportType: 'assets' | 'access_logs' | 'breaches' | 'compliance',
    format: 'csv' | 'excel' | 'pdf',
    filters?: any
  ): Promise<{ download_url: string }> {
    const response = await apiClient.post('/data-protection/export', {
      report_type: reportType,
      format,
      filters
    });
    return response.data;
  }

  // Get data protection compliance status
  async getComplianceStatus(): Promise<{ compliant: boolean; score: number; violations: any[] }> {
    const response = await apiClient.get('/data-protection/compliance');
    return response.data;
  }
}

export const dataProtectionService = new DataProtectionService();
export default dataProtectionService;
