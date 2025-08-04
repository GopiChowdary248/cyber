import { Alert } from 'react-native';

// API Configuration
const API_BASE_URL = 'http://localhost:8000/api/v1';
const API_TIMEOUT = 10000; // 10 seconds

// API Response Types
export interface APIResponse<T> {
  data: T;
  message?: string;
  status: 'success' | 'error';
}

export interface APIError {
  message: string;
  status: number;
  details?: any;
}

// Authentication Types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    username: string;
    email: string;
    role: 'admin' | 'user';
    permissions: string[];
  };
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

// SAST Types
export interface SASTScan {
  id: string;
  project_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scan_type: string;
  created_at: string;
  completed_at?: string;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface SASTVulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  file_path: string;
  line_number: number;
  cwe_id: string;
  cvss_score: number;
  remediation: string;
}

// DAST Types
export interface DASTScan {
  id: string;
  target_url: string;
  scan_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scan_type: string;
  created_at: string;
  completed_at?: string;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_duration?: number;
}

export interface DASTVulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  url: string;
  parameter: string;
  payload: string;
  cwe_id: string;
  cvss_score: number;
  remediation: string;
  evidence: string;
}

// RASP Types
export interface RASPApplication {
  id: string;
  name: string;
  status: 'active' | 'inactive' | 'error';
  application_type: string;
  environment: string;
  created_at: string;
  last_activity: string;
  threats_blocked: number;
  attacks_detected: number;
  false_positives: number;
  protection_enabled: boolean;
  agent_version: string;
  server_url: string;
}

export interface RASPThreat {
  id: string;
  application_id: string;
  threat_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  timestamp: string;
  source_ip: string;
  user_agent: string;
  payload: string;
  action_taken: 'blocked' | 'logged' | 'alerted';
  status: 'active' | 'resolved' | 'false_positive';
}

// Cloud Security Types
export interface CloudResource {
  id: string;
  name: string;
  type: 'ec2' | 's3' | 'rds' | 'lambda' | 'vpc' | 'iam';
  provider: 'aws' | 'azure' | 'gcp';
  region: string;
  status: 'secure' | 'warning' | 'critical' | 'unknown';
  created_at: string;
  last_scan: string;
  compliance_score: number;
  security_issues: number;
  cost: number;
  tags: Record<string, string>;
}

export interface SecurityFinding {
  id: string;
  resource_id: string;
  finding_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  status: 'open' | 'resolved' | 'false_positive';
  created_at: string;
  updated_at: string;
  compliance_frameworks: string[];
}

// Network Security Types
export interface NetworkDevice {
  id: string;
  name: string;
  type: 'firewall' | 'ids' | 'ips' | 'vpn' | 'switch' | 'router';
  ip_address: string;
  mac_address: string;
  status: 'online' | 'offline' | 'warning' | 'error';
  location: string;
  vendor: string;
  model: string;
  firmware_version: string;
  last_seen: string;
  threats_blocked: number;
  attacks_detected: number;
  bandwidth_usage: number;
  cpu_usage: number;
  memory_usage: number;
}

export interface NetworkThreat {
  id: string;
  device_id: string;
  threat_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source_ip: string;
  destination_ip: string;
  port: number;
  protocol: string;
  description: string;
  timestamp: string;
  action_taken: 'blocked' | 'logged' | 'alerted' | 'quarantined';
  status: 'active' | 'resolved' | 'false_positive';
  signature_id: string;
  category: string;
}

// IAM Types
export interface IAMUser {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'user' | 'privileged';
  is_active: boolean;
  mfa_enabled: boolean;
  sso_provider?: string;
  last_login?: string;
  created_at: string;
}

export interface IAMStats {
  total_users: number;
  active_users: number;
  privileged_accounts: number;
  active_sessions: number;
  pending_approvals: number;
  recent_audit_events: number;
  mfa_enabled_users: number;
  sso_enabled_users: number;
}

export interface PrivilegedAccount {
  id: number;
  system_name: string;
  system_type: 'server' | 'database' | 'network_device' | 'cloud';
  username: string;
  account_type: 'admin' | 'root' | 'service_account';
  is_active: boolean;
  last_rotation?: string;
  next_rotation?: string;
  hostname?: string;
  ip_address?: string;
  protocol: string;
}

export interface PrivilegedAccess {
  id: number;
  user_id: number;
  account_id: number;
  status: 'pending' | 'approved' | 'denied' | 'active' | 'expired';
  reason: string;
  requested_at: string;
  expires_at: string;
  approved_at?: string;
  approved_by?: number;
}

// Data Security Types
export interface DataSecurityStats {
  total_encrypted_assets: number;
  active_dlp_incidents: number;
  monitored_databases: number;
  security_score: number;
  compliance_status: Record<string, string>;
  recent_vulnerabilities: number;
  pending_access_requests: number;
}

export interface EncryptionStats {
  total_keys: number;
  active_keys: number;
  encrypted_files: number;
  encrypted_databases: number;
  key_rotation_due: number;
}

export interface DLPStats {
  total_policies: number;
  active_policies: number;
  open_incidents: number;
  resolved_incidents: number;
  false_positives: number;
}

export interface DatabaseSecurityStats {
  monitored_connections: number;
  total_audit_logs: number;
  anomalous_activities: number;
  open_vulnerabilities: number;
  pending_requests: number;
}

export interface EncryptionKey {
  key_id: number;
  key_name: string;
  key_type: string;
  key_size: number;
  created_at: string;
  expires_at?: string;
  is_active: boolean;
}

export interface DLPPolicy {
  policy_id: number;
  policy_name: string;
  policy_type: string;
  enforcement_level: string;
  is_active: boolean;
  created_at: string;
}

export interface DLPIncident {
  incident_id: number;
  policy_id: number;
  violation_type: string;
  severity: string;
  status: string;
  created_at: string;
}

export interface DatabaseConnection {
  connection_id: number;
  db_name: string;
  db_type: string;
  host: string;
  port?: number;
  is_monitored: boolean;
}

export interface DatabaseAccessRequest {
  request_id: number;
  user_id: number;
  db_name: string;
  access_type: string;
  reason: string;
  status: string;
  created_at: string;
}

// Threat Intelligence Types
export interface ThreatIntelligenceStats {
  total_iocs: number;
  new_iocs_today: number;
  active_feeds: number;
  alerts_generated_today: number;
  threats_blocked_today: number;
  avg_confidence_score: number;
  threat_level_distribution: { [key: string]: number };
  top_ioc_types: Array<{ type: string; count: number }>;
  recent_alerts: Array<any>;
  feed_status_summary: { [key: string]: number };
}

export interface ThreatFeed {
  id: number;
  name: string;
  feed_type: string;
  url: string;
  status: string;
  last_update: string;
  is_enabled: boolean;
  description?: string;
}

export interface IoC {
  id: number;
  value: string;
  ioc_type: string;
  threat_level: string;
  confidence_score: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
  is_active: boolean;
}

export interface ThreatAlert {
  id: number;
  title: string;
  description?: string;
  threat_level: string;
  source: string;
  is_resolved: boolean;
  created_at: string;
}

export interface IntegrationConfig {
  id: number;
  name: string;
  integration_type: string;
  endpoint_url: string;
  is_enabled: boolean;
  auto_block: boolean;
  block_threshold: string;
}

// API Service Class
class APIService {
  private baseURL: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  // Set authentication tokens
  setTokens(accessToken: string, refreshToken: string) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  // Clear authentication tokens
  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
  }

  // Get authorization headers
  private getAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  // Generic API request method
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const headers = this.getAuthHeaders();

    const config: RequestInit = {
      headers,
      ...options,
    };

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);

      const response = await fetch(url, {
        ...config,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new APIError({
          message: errorData.message || `HTTP ${response.status}`,
          status: response.status,
          details: errorData,
        });
      }

      const data = await response.json();
      return data;
    } catch (error) {
      if (error instanceof APIError) {
        throw error;
      }

      if (error.name === 'AbortError') {
        throw new APIError({
          message: 'Request timeout',
          status: 408,
        });
      }

      throw new APIError({
        message: error.message || 'Network error',
        status: 0,
      });
    }
  }

  // Authentication APIs
  async login(credentials: LoginRequest): Promise<LoginResponse> {
    const response = await this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    this.setTokens(response.access_token, response.refresh_token);
    return response;
  }

  async logout(): Promise<void> {
    if (this.refreshToken) {
      try {
        await this.request('/auth/logout', {
          method: 'POST',
          body: JSON.stringify({ refresh_token: this.refreshToken }),
        });
      } catch (error) {
        console.warn('Logout request failed:', error);
      }
    }

    this.clearTokens();
  }

  async refreshAccessToken(): Promise<LoginResponse> {
    if (!this.refreshToken) {
      throw new APIError({
        message: 'No refresh token available',
        status: 401,
      });
    }

    const response = await this.request<LoginResponse>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: this.refreshToken }),
    });

    this.setTokens(response.access_token, response.refresh_token);
    return response;
  }

  // SAST APIs
  async getSASTScans(): Promise<SASTScan[]> {
    return this.request<SASTScan[]>('/sast/scans');
  }

  async getSASTVulnerabilities(scanId: string): Promise<SASTVulnerability[]> {
    return this.request<SASTVulnerability[]>(`/sast/scans/${scanId}/vulnerabilities`);
  }

  async startSASTScan(projectData: { name: string; repository_url: string }): Promise<SASTScan> {
    return this.request<SASTScan>('/sast/scans', {
      method: 'POST',
      body: JSON.stringify(projectData),
    });
  }

  // DAST APIs
  async getDASTScans(): Promise<DASTScan[]> {
    return this.request<DASTScan[]>('/dast/scans');
  }

  async getDASTVulnerabilities(scanId: string): Promise<DASTVulnerability[]> {
    return this.request<DASTVulnerability[]>(`/dast/scans/${scanId}/vulnerabilities`);
  }

  async startDASTScan(scanData: { target_url: string; scan_name: string; scan_type: string }): Promise<DASTScan> {
    return this.request<DASTScan>('/dast/scans', {
      method: 'POST',
      body: JSON.stringify(scanData),
    });
  }

  // RASP APIs
  async getRASPApplications(): Promise<RASPApplication[]> {
    return this.request<RASPApplication[]>('/rasp/applications');
  }

  async getRASPThreats(applicationId: string): Promise<RASPThreat[]> {
    return this.request<RASPThreat[]>(`/rasp/applications/${applicationId}/threats`);
  }

  async updateRASPProtection(applicationId: string, enabled: boolean): Promise<void> {
    return this.request<void>(`/rasp/applications/${applicationId}/protection`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    });
  }

  async getRASPMetrics(): Promise<{
    threats_blocked: number;
    attacks_detected: number;
    false_positives: number;
    response_time_avg: number;
    uptime_percentage: number;
  }> {
    return this.request('/rasp/metrics');
  }

  // Cloud Security APIs
  async getCloudResources(provider?: string): Promise<CloudResource[]> {
    const endpoint = provider ? `/cloud-security/resources?provider=${provider}` : '/cloud-security/resources';
    return this.request<CloudResource[]>(endpoint);
  }

  async getCloudFindings(resourceId: string): Promise<SecurityFinding[]> {
    return this.request<SecurityFinding[]>(`/cloud-security/resources/${resourceId}/findings`);
  }

  async updateFindingStatus(findingId: string, status: string): Promise<void> {
    return this.request<void>(`/cloud-security/findings/${findingId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  async getCloudMetrics(): Promise<{
    total_resources: number;
    secure_resources: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    compliance_score_avg: number;
    estimated_cost: number;
  }> {
    return this.request('/cloud-security/metrics');
  }

  // Network Security APIs
  async getNetworkDevices(deviceType?: string): Promise<NetworkDevice[]> {
    const endpoint = deviceType ? `/network-security/devices?type=${deviceType}` : '/network-security/devices';
    return this.request<NetworkDevice[]>(endpoint);
  }

  async getNetworkThreats(deviceId: string): Promise<NetworkThreat[]> {
    return this.request<NetworkThreat[]>(`/network-security/devices/${deviceId}/threats`);
  }

  async updateDeviceStatus(deviceId: string, status: string): Promise<void> {
    return this.request<void>(`/network-security/devices/${deviceId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  async getNetworkMetrics(): Promise<{
    total_devices: number;
    online_devices: number;
    threats_blocked: number;
    attacks_detected: number;
    bandwidth_avg: number;
    uptime_percentage: number;
    security_score: number;
  }> {
    return this.request('/network-security/metrics');
  }

  // IAM API Methods
  async getIAMStats(): Promise<IAMStats> {
    return this.request('/iam/dashboard/stats');
  }

  async getIAMUsers(limit?: number, search?: string): Promise<{ users: IAMUser[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (search) params.append('search', search);
    return this.request(`/iam/users?${params.toString()}`);
  }

  async createIAMUser(userData: {
    username: string;
    email: string;
    password: string;
    full_name?: string;
    role?: string;
  }): Promise<IAMUser> {
    return this.request('/iam/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData),
    });
  }

  async getPrivilegedAccounts(limit?: number): Promise<{ accounts: PrivilegedAccount[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/iam/pam/accounts?${params.toString()}`);
  }

  async createPrivilegedAccount(accountData: {
    system_name: string;
    system_type: string;
    username: string;
    password: string;
    account_type: string;
    hostname?: string;
    ip_address?: string;
    protocol?: string;
  }): Promise<PrivilegedAccount> {
    return this.request('/iam/pam/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(accountData),
    });
  }

  async getPendingAccessRequests(limit?: number): Promise<{ access_requests: PrivilegedAccess[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/iam/pam/access/pending?${params.toString()}`);
  }

  async approvePrivilegedAccess(accessId: number): Promise<PrivilegedAccess> {
    return this.request(`/iam/pam/access/${accessId}/approve`, {
      method: 'POST',
    });
  }

  async denyPrivilegedAccess(accessId: number): Promise<PrivilegedAccess> {
    return this.request(`/iam/pam/access/${accessId}/deny`, {
      method: 'POST',
    });
  }

  async requestPrivilegedAccess(accessData: {
    account_id: number;
    reason: string;
    expires_at: string;
  }): Promise<PrivilegedAccess> {
    return this.request('/iam/pam/access/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(accessData),
    });
  }

  async getAuditLogs(params?: {
    skip?: number;
    limit?: number;
    user_id?: number;
    action?: string;
    target_type?: string;
    risk_level?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<{ logs: any[]; total: number; skip: number; limit: number }> {
    const queryParams = new URLSearchParams();
    if (params?.skip) queryParams.append('skip', params.skip.toString());
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.user_id) queryParams.append('user_id', params.user_id.toString());
    if (params?.action) queryParams.append('action', params.action);
    if (params?.target_type) queryParams.append('target_type', params.target_type);
    if (params?.risk_level) queryParams.append('risk_level', params.risk_level);
    if (params?.start_date) queryParams.append('start_date', params.start_date);
    if (params?.end_date) queryParams.append('end_date', params.end_date);
    
    return this.request(`/iam/audit/logs?${queryParams.toString()}`);
  }

  // Data Security API Methods
  async getDataSecurityStats(): Promise<DataSecurityStats> {
    return this.request('/data-security/dashboard/stats');
  }

  async getEncryptionStats(): Promise<EncryptionStats> {
    return this.request('/data-security/encryption/stats');
  }

  async getDLPStats(): Promise<DLPStats> {
    return this.request('/data-security/dlp/stats');
  }

  async getDatabaseSecurityStats(): Promise<DatabaseSecurityStats> {
    return this.request('/data-security/database/security/stats');
  }

  async getEncryptionKeys(limit?: number): Promise<{ keys: EncryptionKey[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/data-security/encryption/keys?${params.toString()}`);
  }

  async getDLPPolicies(limit?: number): Promise<{ policies: DLPPolicy[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/data-security/dlp/policies?${params.toString()}`);
  }

  async getDLPIncidents(limit?: number): Promise<{ incidents: DLPIncident[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/data-security/dlp/incidents?${params.toString()}`);
  }

  async getDatabaseConnections(limit?: number): Promise<{ connections: DatabaseConnection[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/data-security/database/connections?${params.toString()}`);
  }

  async getDatabaseAccessRequests(limit?: number): Promise<{ requests: DatabaseAccessRequest[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/data-security/database/access/requests?${params.toString()}`);
  }

  // Threat Intelligence API Methods
  async getThreatIntelligenceStats(): Promise<ThreatIntelligenceStats> {
    return this.request('/threat-intelligence/dashboard/stats');
  }

  async getThreatFeeds(limit?: number): Promise<{ feeds: ThreatFeed[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/threat-intelligence/feeds?${params.toString()}`);
  }

  async createThreatFeed(feedData: {
    name: string;
    feed_type: string;
    url: string;
    api_key?: string;
    update_frequency?: number;
    description?: string;
    is_enabled?: boolean;
  }): Promise<ThreatFeed> {
    return this.request('/threat-intelligence/feeds', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(feedData),
    });
  }

  async updateThreatFeed(feedId: number, updateData?: any): Promise<ThreatFeed> {
    if (updateData) {
      return this.request(`/threat-intelligence/feeds/${feedId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updateData),
      });
    } else {
      return this.request(`/threat-intelligence/feeds/${feedId}/update`, {
        method: 'POST',
      });
    }
  }

  async getIOCs(limit?: number, ioc_type?: string, threat_level?: string): Promise<{ iocs: IoC[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (ioc_type) params.append('ioc_type', ioc_type);
    if (threat_level) params.append('threat_level', threat_level);
    return this.request(`/threat-intelligence/iocs?${params.toString()}`);
  }

  async searchIOCs(query: string, limit?: number): Promise<{ iocs: IoC[]; total: number }> {
    const params = new URLSearchParams();
    params.append('query', query);
    if (limit) params.append('limit', limit.toString());
    return this.request(`/threat-intelligence/iocs/search?${params.toString()}`);
  }

  async createIoC(iocData: {
    value: string;
    ioc_type: string;
    threat_level: string;
    confidence_score: number;
    feed_id: number;
    tags?: string[];
    metadata?: any;
  }): Promise<IoC> {
    return this.request('/threat-intelligence/iocs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(iocData),
    });
  }

  async updateIoC(iocId: number, updateData: {
    threat_level?: string;
    confidence_score?: number;
    tags?: string[];
    metadata?: any;
    is_active?: boolean;
  }): Promise<IoC> {
    return this.request(`/threat-intelligence/iocs/${iocId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updateData),
    });
  }

  async getThreatAlerts(limit?: number, resolved?: boolean): Promise<{ alerts: ThreatAlert[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (resolved !== undefined) params.append('resolved', resolved.toString());
    return this.request(`/threat-intelligence/alerts?${params.toString()}`);
  }

  async createThreatAlert(alertData: {
    title: string;
    description?: string;
    ioc_id: number;
    threat_level: string;
    source: string;
  }): Promise<ThreatAlert> {
    return this.request('/threat-intelligence/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alertData),
    });
  }

  async updateThreatAlert(alertId: number, updateData: {
    title?: string;
    description?: string;
    threat_level?: string;
    is_resolved?: boolean;
    resolved_by?: string;
  }): Promise<ThreatAlert> {
    return this.request(`/threat-intelligence/alerts/${alertId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updateData),
    });
  }

  async getIntegrations(limit?: number): Promise<{ integrations: IntegrationConfig[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/threat-intelligence/integrations?${params.toString()}`);
  }

  async createIntegration(integrationData: {
    name: string;
    integration_type: string;
    endpoint_url: string;
    api_key?: string;
    credentials?: any;
    is_enabled?: boolean;
    auto_block?: boolean;
    block_threshold?: string;
  }): Promise<IntegrationConfig> {
    return this.request('/threat-intelligence/integrations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(integrationData),
    });
  }

  async exportIOCsToIntegration(integrationId: number, iocIds: number[], format?: string): Promise<any> {
    return this.request(`/threat-intelligence/integrations/${integrationId}/export`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ioc_ids: iocIds,
        format: format || 'stix',
        include_metadata: true,
      }),
    });
  }

  async getIoCThreatScore(iocId: number): Promise<{
    ioc_id: number;
    threat_score: number;
    threat_level: string;
    confidence_score: number;
  }> {
    return this.request(`/threat-intelligence/iocs/${iocId}/score`);
  }

  async getFeedLogs(feedId: number, limit?: number): Promise<{ logs: any[]; total: number }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    return this.request(`/threat-intelligence/feeds/${feedId}/logs?${params.toString()}`);
  }

  async getThreatIntelligenceHealth(): Promise<any> {
    return this.request('/threat-intelligence/health');
  }

  // Error handling utility
  handleError(error: APIError, context?: string): void {
    console.error(`API Error${context ? ` in ${context}` : ''}:`, error);

    let message = error.message;
    
    if (error.status === 401) {
      message = 'Authentication failed. Please log in again.';
      this.clearTokens();
    } else if (error.status === 403) {
      message = 'Access denied. You don\'t have permission to perform this action.';
    } else if (error.status === 404) {
      message = 'Resource not found.';
    } else if (error.status === 500) {
      message = 'Server error. Please try again later.';
    } else if (error.status === 0) {
      message = 'Network error. Please check your connection.';
    }

    Alert.alert('Error', message);
  }
}

// Create and export a singleton instance
export const apiService = new APIService();

// Export the class for testing or custom instances
export default APIService; 