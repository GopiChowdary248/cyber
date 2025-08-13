import { apiClient, apiCallWithRetry } from '../utils/apiClient';
import { API_ENDPOINTS } from './integrationService';

// Data Security service interfaces
export interface EncryptionKeyResponse {
  id: number;
  name: string;
  key_type: string;
  algorithm: string;
  key_size: number;
  is_active: boolean;
  created_at: string;
  expires_at?: string;
  last_rotated?: string;
}

export interface EncryptionKeyCreate {
  name: string;
  key_type: string;
  algorithm: string;
  key_size: number;
  expires_at?: string;
}

export interface EncryptionKeyUpdate {
  name?: string;
  is_active?: boolean;
  expires_at?: string;
}

export interface DLPPolicyResponse {
  id: number;
  name: string;
  description: string;
  policy_type: string;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DLPPolicyCreate {
  name: string;
  description: string;
  policy_type: string;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface DLPIncidentResponse {
  id: number;
  policy_id: number;
  policy_name: string;
  content_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  detected_at: string;
  resolved_at?: string;
  details: Record<string, any>;
}

export interface DatabaseConnectionResponse {
  id: number;
  name: string;
  db_type: string;
  host: string;
  port: number;
  database: string;
  is_monitored: boolean;
  encryption_enabled: boolean;
  created_at: string;
}

export interface DatabaseAuditLogResponse {
  id: number;
  connection_id: number;
  user_id: string;
  action: string;
  query?: string;
  table?: string;
  timestamp: string;
  ip_address: string;
  is_anomalous: boolean;
  risk_score: number;
}

export interface DatabaseAccessRequestResponse {
  id: number;
  user_id: number;
  connection_id: number;
  reason: string;
  requested_access: string;
  status: 'pending' | 'approved' | 'denied';
  requested_at: string;
  approved_at?: string;
  approved_by?: number;
}

export interface DataSecurityStats {
  total_encrypted_assets: number;
  active_encryption_keys: number;
  dlp_incidents_today: number;
  dlp_incidents_this_week: number;
  database_connections: number;
  monitored_databases: number;
  anomalous_activities: number;
  compliance_score: number;
}

export interface EncryptionStats {
  total_keys: number;
  active_keys: number;
  expired_keys: number;
  keys_by_algorithm: Record<string, number>;
  keys_by_type: Record<string, number>;
  last_key_rotation: string;
}

export interface DLPStats {
  total_policies: number;
  active_policies: number;
  incidents_by_severity: Record<string, number>;
  incidents_by_status: Record<string, number>;
  incidents_trend: {
    date: string;
    count: number;
  }[];
}

export interface DatabaseSecurityStats {
  total_connections: number;
  monitored_connections: number;
  encrypted_connections: number;
  access_requests: number;
  pending_requests: number;
  anomalous_activities: number;
  risk_score: number;
}

export interface DataSecurityHealthCheck {
  overall_status: 'healthy' | 'degraded' | 'unhealthy';
  encryption_status: 'healthy' | 'degraded' | 'unhealthy';
  dlp_status: 'healthy' | 'degraded' | 'unhealthy';
  database_status: 'healthy' | 'degraded' | 'unhealthy';
  issues: string[];
  last_check: string;
}

/**
 * Data Security Service - Handles all data security operations
 */
class DataSecurityService {
  private baseUrl = '/data-security';

  /**
   * Get data security dashboard statistics
   */
  async getDashboardStats(): Promise<DataSecurityStats> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/dashboard/stats`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get data security stats:', error);
      throw error;
    }
  }

  /**
   * Get encryption statistics
   */
  async getEncryptionStats(): Promise<EncryptionStats> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/encryption/stats`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get encryption stats:', error);
      throw error;
    }
  }

  /**
   * Get DLP statistics
   */
  async getDLPStats(): Promise<DLPStats> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/dlp/stats`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get DLP stats:', error);
      throw error;
    }
  }

  /**
   * Get database security statistics
   */
  async getDatabaseSecurityStats(): Promise<DatabaseSecurityStats> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/database/security/stats`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get database security stats:', error);
      throw error;
    }
  }

  /**
   * Get data security health check
   */
  async getHealthCheck(): Promise<DataSecurityHealthCheck> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/health`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get data security health check:', error);
      throw error;
    }
  }

  // Encryption Key Management
  /**
   * Create a new encryption key
   */
  async createEncryptionKey(keyData: EncryptionKeyCreate): Promise<EncryptionKeyResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/encryption/keys`, keyData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to create encryption key:', error);
      throw error;
    }
  }

  /**
   * Get encryption keys with filtering
   */
  async getEncryptionKeys(params?: {
    skip?: number;
    limit?: number;
    key_type?: string;
    is_active?: boolean;
  }): Promise<{
    keys: EncryptionKeyResponse[];
    total: number;
    page: number;
    size: number;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/encryption/keys`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get encryption keys:', error);
      throw error;
    }
  }

  /**
   * Update encryption key
   */
  async updateEncryptionKey(keyId: number, keyData: EncryptionKeyUpdate): Promise<EncryptionKeyResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(`${this.baseUrl}/encryption/keys/${keyId}`, keyData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to update encryption key:', error);
      throw error;
    }
  }

  /**
   * Rotate encryption key
   */
  async rotateEncryptionKey(keyId: number): Promise<{ message: string }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/encryption/keys/${keyId}/rotate`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to rotate encryption key:', error);
      throw error;
    }
  }

  /**
   * Encrypt a file
   */
  async encryptFile(filePath: string, keyId: number): Promise<{ message: string; encrypted_path: string }> {
    try {
      const formData = new FormData();
      formData.append('file_path', filePath);
      formData.append('key_id', keyId.toString());
      
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/encryption/files/encrypt`, formData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to encrypt file:', error);
      throw error;
    }
  }

  // DLP Policy Management
  /**
   * Create a new DLP policy
   */
  async createDLPPolicy(policyData: DLPPolicyCreate): Promise<DLPPolicyResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/dlp/policies`, policyData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to create DLP policy:', error);
      throw error;
    }
  }

  /**
   * Get DLP policies with filtering
   */
  async getDLPPolicies(params?: {
    skip?: number;
    limit?: number;
    policy_type?: string;
    is_active?: boolean;
  }): Promise<{
    policies: DLPPolicyResponse[];
    total: number;
    page: number;
    size: number;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/dlp/policies`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get DLP policies:', error);
      throw error;
    }
  }

  /**
   * Update DLP policy
   */
  async updateDLPPolicy(policyId: number, policyData: Partial<DLPPolicyCreate>): Promise<DLPPolicyResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(`${this.baseUrl}/dlp/policies/${policyId}`, policyData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to update DLP policy:', error);
      throw error;
    }
  }

  /**
   * Get DLP incidents with filtering
   */
  async getDLPIncidents(params?: {
    skip?: number;
    limit?: number;
    status?: string;
    severity?: string;
  }): Promise<{
    incidents: DLPIncidentResponse[];
    total: number;
    page: number;
    size: number;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/dlp/incidents`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get DLP incidents:', error);
      throw error;
    }
  }

  /**
   * Update DLP incident
   */
  async updateDLPIncident(incidentId: number, incidentData: Partial<DLPIncidentResponse>): Promise<DLPIncidentResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(`${this.baseUrl}/dlp/incidents/${incidentId}`, incidentData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to update DLP incident:', error);
      throw error;
    }
  }

  /**
   * Evaluate content against DLP policies
   */
  async evaluateContent(content: string, policyIds: number[]): Promise<{
    matches: Array<{
      policy_id: number;
      policy_name: string;
      severity: string;
      confidence: number;
      matched_patterns: string[];
    }>;
    risk_score: number;
  }> {
    try {
      const formData = new FormData();
      formData.append('content', content);
      policyIds.forEach(id => formData.append('policy_ids', id.toString()));
      
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/dlp/content/evaluate`, formData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to evaluate content:', error);
      throw error;
    }
  }

  // Database Security Management
  /**
   * Add database connection
   */
  async addDatabaseConnection(connectionData: {
    name: string;
    db_type: string;
    host: string;
    port: number;
    database: string;
    is_monitored: boolean;
    encryption_enabled: boolean;
  }): Promise<DatabaseConnectionResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/database/connections`, connectionData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to add database connection:', error);
      throw error;
    }
  }

  /**
   * Get database connections with filtering
   */
  async getDatabaseConnections(params?: {
    skip?: number;
    limit?: number;
    db_type?: string;
    is_monitored?: boolean;
  }): Promise<{
    connections: DatabaseConnectionResponse[];
    total: number;
    page: number;
    size: number;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/database/connections`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get database connections:', error);
      throw error;
    }
  }

  /**
   * Get database activity/audit logs
   */
  async getDatabaseActivity(params?: {
    skip?: number;
    limit?: number;
    connection_id?: number;
    user_id?: string;
    is_anomalous?: boolean;
  }): Promise<{
    logs: DatabaseAuditLogResponse[];
    total: number;
    page: number;
    size: number;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/database/activity`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get database activity:', error);
      throw error;
    }
  }

  /**
   * Request database access
   */
  async requestDatabaseAccess(requestData: {
    connection_id: number;
    reason: string;
    requested_access: string;
  }): Promise<DatabaseAccessRequestResponse> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.post(`${this.baseUrl}/database/access/request`, requestData)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to request database access:', error);
      throw error;
    }
  }

  /**
   * Get database access requests
   */
  async getDatabaseAccessRequests(params?: {
    skip?: number;
    limit?: number;
    status?: string;
    user_id?: number;
  }): Promise<{
    requests: DatabaseAccessRequestResponse[];
    total: number;
    page: number;
    size: number;
  }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.get(`${this.baseUrl}/database/access/requests`, { params })
      );
      return response.data;
    } catch (error) {
      console.error('Failed to get database access requests:', error);
      throw error;
    }
  }

  /**
   * Approve database access request
   */
  async approveDatabaseAccess(requestId: number): Promise<{ message: string }> {
    try {
      const response = await apiCallWithRetry(() => 
        apiClient.put(`${this.baseUrl}/database/access/requests/${requestId}/approve`)
      );
      return response.data;
    } catch (error) {
      console.error('Failed to approve database access:', error);
      throw error;
    }
  }

  /**
   * Get comprehensive data security overview
   */
  async getDataSecurityOverview(): Promise<{
    stats: DataSecurityStats;
    encryption: EncryptionStats;
    dlp: DLPStats;
    database: DatabaseSecurityStats;
    health: DataSecurityHealthCheck;
  }> {
    try {
      const [stats, encryption, dlp, database, health] = await Promise.all([
        this.getDashboardStats(),
        this.getEncryptionStats(),
        this.getDLPStats(),
        this.getDatabaseSecurityStats(),
        this.getHealthCheck()
      ]);

      return {
        stats,
        encryption,
        dlp,
        database,
        health
      };
    } catch (error) {
      console.error('Failed to get data security overview:', error);
      throw error;
    }
  }

  /**
   * Get data security trends
   */
  async getDataSecurityTrends(days: number = 30): Promise<{
    encryption_trend: Array<{ date: string; active_keys: number }>;
    dlp_incidents_trend: Array<{ date: string; count: number }>;
    database_activity_trend: Array<{ date: string; activities: number }>;
    compliance_score_trend: Array<{ date: string; score: number }>;
  }> {
    try {
      // This would need corresponding backend endpoints
      // For now, return placeholder data
      const dates = Array.from({ length: days }, (_, i) => {
        const date = new Date();
        date.setDate(date.getDate() - i);
        return date.toISOString().split('T')[0];
      }).reverse();

      return {
        encryption_trend: dates.map(date => ({
          date,
          active_keys: Math.floor(Math.random() * 10) + 5
        })),
        dlp_incidents_trend: dates.map(date => ({
          date,
          count: Math.floor(Math.random() * 20)
        })),
        database_activity_trend: dates.map(date => ({
          date,
          activities: Math.floor(Math.random() * 100) + 50
        })),
        compliance_score_trend: dates.map(date => ({
          date,
          score: Math.floor(Math.random() * 20) + 80
        }))
      };
    } catch (error) {
      console.error('Failed to get data security trends:', error);
      throw error;
    }
  }
}

export default new DataSecurityService();
