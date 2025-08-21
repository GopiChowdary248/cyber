import { apiClient } from '../utils/apiClient';

// Base API configuration
const API_BASE = '/api/v1';

// Types for comprehensive security platform
export interface SecurityModule {
  module: string;
  description: string;
  status: string;
  features: string[];
}

export interface ApiResponse<T> {
  data: T;
  status: string;
  message?: string;
}

// ===== DAST (Dynamic Application Security Testing) =====
export interface DASTProject {
  id: string;
  name: string;
  url: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface DASTScan {
  id: string;
  project_id: string;
  status: string;
  progress: number;
  findings: number;
  started_at: string;
  completed_at?: string;
}

export class DASTService {
  static async getProjects(): Promise<DASTProject[]> {
    const response = await apiClient.get(`${API_BASE}/dast/projects`);
    return response.data;
  }

  static async createProject(project: Partial<DASTProject>): Promise<DASTProject> {
    const response = await apiClient.post(`${API_BASE}/dast/projects`, project);
    return response.data;
  }

  static async startScan(projectId: string, config: any): Promise<DASTScan> {
    const response = await apiClient.post(`${API_BASE}/dast/scanner/start`, {
      project_id: projectId,
      ...config
    });
    return response.data;
  }

  static async getScanStatus(scanId: string): Promise<DASTScan> {
    const response = await apiClient.get(`${API_BASE}/dast/scanner/status/${scanId}`);
    return response.data;
  }
}

// ===== SAST (Static Application Security Testing) =====
export interface SASTProject {
  id: string;
  name: string;
  repository_url: string;
  language: string;
  status: string;
  last_scan: string;
  vulnerabilities: number;
}

export class SASTService {
  static async getProjects(): Promise<SASTProject[]> {
    const response = await apiClient.get(`${API_BASE}/sast/projects`);
    return response.data;
  }

  static async analyzeCode(projectId: string, sourceCode: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/sast/analyze`, {
      project_id: projectId,
      source_code: sourceCode
    });
    return response.data;
  }
}

// ===== RASP (Runtime Application Self-Protection) =====
export interface RASPAgent {
  id: string;
  name: string;
  status: string;
  application: string;
  last_seen: string;
  threats_blocked: number;
}

export class RASPService {
  static async getAgents(): Promise<RASPAgent[]> {
    const response = await apiClient.get(`${API_BASE}/rasp/agents`);
    return response.data;
  }

  static async deployAgent(application: string, config: any): Promise<RASPAgent> {
    const response = await apiClient.post(`${API_BASE}/rasp/agents`, {
      application,
      ...config
    });
    return response.data;
  }
}

// ===== Cloud Security =====
export interface CloudAccount {
  id: string;
  provider: 'aws' | 'azure' | 'gcp';
  name: string;
  region: string;
  status: string;
  security_score: number;
}

export class CloudSecurityService {
  static async getAccounts(): Promise<CloudAccount[]> {
    const response = await apiClient.get(`${API_BASE}/cloud-security/accounts`);
    return response.data;
  }

  static async scanAccount(accountId: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/cloud-security/scan/${accountId}`);
    return response.data;
  }
}

// ===== Endpoint Security =====
export interface EndpointDevice {
  id: string;
  name: string;
  type: string;
  os: string;
  status: string;
  last_seen: string;
  threats: number;
}

export class EndpointSecurityService {
  static async getDevices(): Promise<EndpointDevice[]> {
    const response = await apiClient.get(`${API_BASE}/endpoint-security/devices`);
    return response.data;
  }

  static async deployProtection(deviceId: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/endpoint-security/protect/${deviceId}`);
    return response.data;
  }
}

// ===== Network Security =====
export interface NetworkDevice {
  id: string;
  name: string;
  type: 'firewall' | 'ids' | 'switch' | 'router';
  status: string;
  ip_address: string;
  threats_blocked: number;
}

export class NetworkSecurityService {
  static async getDevices(): Promise<NetworkDevice[]> {
    const response = await apiClient.get(`${API_BASE}/network-security/devices`);
    return response.data;
  }

  static async analyzeTraffic(): Promise<any> {
    const response = await apiClient.get(`${API_BASE}/network-security/traffic-analysis`);
    return response.data;
  }
}

// ===== IAM (Identity and Access Management) =====
export interface IAMUser {
  id: string;
  username: string;
  email: string;
  role: string;
  status: string;
  last_login: string;
  mfa_enabled: boolean;
}

export class IAMService {
  static async getUsers(): Promise<IAMUser[]> {
    const response = await apiClient.get(`${API_BASE}/iam/users`);
    return response.data;
  }

  static async createUser(user: Partial<IAMUser>): Promise<IAMUser> {
    const response = await apiClient.post(`${API_BASE}/iam/users`, user);
    return response.data;
  }

  static async enableMFA(userId: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/iam/users/${userId}/mfa`);
    return response.data;
  }
}

// ===== Data Security =====
export interface DataAsset {
  id: string;
  name: string;
  type: string;
  classification: string;
  location: string;
  encryption_status: string;
}

export class DataSecurityService {
  static async getAssets(): Promise<DataAsset[]> {
    const response = await apiClient.get(`${API_BASE}/data-security/assets`);
    return response.data;
  }

  static async encryptAsset(assetId: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/data-security/encrypt/${assetId}`);
    return response.data;
  }
}

// ===== Incident Management =====
export interface SecurityIncident {
  id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  status: string;
  assigned_to: string;
  created_at: string;
  updated_at: string;
}

export class IncidentService {
  static async getIncidents(): Promise<SecurityIncident[]> {
    const response = await apiClient.get(`${API_BASE}/incidents`);
    return response.data;
  }

  static async createIncident(incident: Partial<SecurityIncident>): Promise<SecurityIncident> {
    const response = await apiClient.post(`${API_BASE}/incidents`, incident);
    return response.data;
  }

  static async updateStatus(incidentId: string, status: string): Promise<any> {
    const response = await apiClient.patch(`${API_BASE}/incidents/${incidentId}`, { status });
    return response.data;
  }
}

// ===== Threat Intelligence =====
export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash';
  value: string;
  threat_level: string;
  source: string;
  first_seen: string;
}

export class ThreatIntelligenceService {
  static async getIndicators(): Promise<ThreatIndicator[]> {
    const response = await apiClient.get(`${API_BASE}/threat-intelligence/iocs`);
    return response.data;
  }

  static async analyzeIndicator(indicator: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/threat-intelligence/analyze`, {
      indicator
    });
    return response.data;
  }
}

// ===== Compliance =====
export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  status: string;
  score: number;
  last_assessment: string;
}

export class ComplianceService {
  static async getFrameworks(): Promise<ComplianceFramework[]> {
    const response = await apiClient.get(`${API_BASE}/compliance/frameworks`);
    return response.data;
  }

  static async assessCompliance(frameworkId: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/compliance/assess/${frameworkId}`);
    return response.data;
  }
}

// ===== DevSecOps =====
export interface DevSecOpsPipeline {
  id: string;
  name: string;
  type: string;
  status: string;
  security_gates: number;
  last_run: string;
}

export class DevSecOpsService {
  static async getPipelines(): Promise<DevSecOpsPipeline[]> {
    const response = await apiClient.get(`${API_BASE}/devsecops/pipelines`);
    return response.data;
  }

  static async runSecurityScan(pipelineId: string): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/devsecops/scan/${pipelineId}`);
    return response.data;
  }
}

// ===== AI/ML =====
export interface AIModel {
  id: string;
  name: string;
  type: string;
  status: string;
  accuracy: number;
  last_trained: string;
}

export class AIService {
  static async getModels(): Promise<AIModel[]> {
    const response = await apiClient.get(`${API_BASE}/ai-ml/models`);
    return response.data;
  }

  static async predictThreat(data: any): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/ai-ml/predict`, data);
    return response.data;
  }
}

// ===== Admin =====
export interface SystemStatus {
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  active_users: number;
  uptime: string;
}

export class AdminService {
  static async getSystemStatus(): Promise<SystemStatus> {
    const response = await apiClient.get(`${API_BASE}/admin/system-status`);
    return response.data;
  }

  static async getSystemLogs(): Promise<any[]> {
    const response = await apiClient.get(`${API_BASE}/admin/system-logs`);
    return response.data;
  }
}

// ===== User Management =====
export interface UserProfile {
  id: string;
  username: string;
  email: string;
  full_name: string;
  role: string;
  department: string;
  last_active: string;
}

export class UserManagementService {
  static async getUsers(): Promise<UserProfile[]> {
    const response = await apiClient.get(`${API_BASE}/users`);
    return response.data;
  }

  static async updateProfile(userId: string, profile: Partial<UserProfile>): Promise<UserProfile> {
    const response = await apiClient.patch(`${API_BASE}/users/${userId}`, profile);
    return response.data;
  }
}

// ===== Audit & Logging =====
export interface AuditLog {
  id: string;
  user: string;
  action: string;
  resource: string;
  timestamp: string;
  ip_address: string;
  status: string;
}

export class AuditService {
  static async getLogs(): Promise<AuditLog[]> {
    const response = await apiClient.get(`${API_BASE}/audit/logs`);
    return response.data;
  }

  static async exportLogs(format: string): Promise<any> {
    const response = await apiClient.get(`${API_BASE}/audit/export`, {
      params: { format }
    });
    return response.data;
  }
}

// ===== Reporting & Analytics =====
export interface SecurityReport {
  id: string;
  title: string;
  type: string;
  generated_at: string;
  format: string;
  size: number;
}

export class ReportingService {
  static async getReports(): Promise<SecurityReport[]> {
    const response = await apiClient.get(`${API_BASE}/reporting/reports`);
    return response.data;
  }

  static async generateReport(type: string, parameters: any): Promise<SecurityReport> {
    const response = await apiClient.post(`${API_BASE}/reporting/generate`, {
      type,
      parameters
    });
    return response.data;
  }
}

// ===== Integrations =====
export interface Integration {
  id: string;
  name: string;
  type: string;
  status: string;
  last_sync: string;
  config: any;
}

export class IntegrationService {
  static async getIntegrations(): Promise<Integration[]> {
    const response = await apiClient.get(`${API_BASE}/integrations`);
    return response.data;
  }

  static async configureIntegration(integrationId: string, config: any): Promise<any> {
    const response = await apiClient.post(`${API_BASE}/integrations/${integrationId}/configure`, config);
    return response.data;
  }
}

// ===== Comprehensive Security Dashboard Service =====
export class ComprehensiveSecurityService {
  static async getPlatformOverview(): Promise<any> {
    const response = await apiClient.get('/api/status');
    return response.data;
  }

  static async getHealthStatus(): Promise<any> {
    const response = await apiClient.get('/health');
    return response.data;
  }

  static async getModuleStatus(module: string): Promise<SecurityModule> {
    const response = await apiClient.get(`${API_BASE}/${module}`);
    return response.data;
  }

  // Get summary statistics for dashboard
  static async getDashboardStats(): Promise<any> {
    try {
      const [
        dastProjects,
        sastProjects,
        incidents,
        threats,
        users,
        compliance
      ] = await Promise.all([
        DASTService.getProjects(),
        SASTService.getProjects(),
        IncidentService.getIncidents(),
        ThreatIntelligenceService.getIndicators(),
        UserManagementService.getUsers(),
        ComplianceService.getFrameworks()
      ]);

      return {
        dast: {
          total_projects: dastProjects.length,
          active_scans: dastProjects.filter(p => p.status === 'active').length
        },
        sast: {
          total_projects: sastProjects.length,
          vulnerabilities: sastProjects.reduce((sum, p) => sum + p.vulnerabilities, 0)
        },
        incidents: {
          total: incidents.length,
          critical: incidents.filter(i => i.severity === 'Critical').length,
          open: incidents.filter(i => i.status === 'New').length
        },
        threats: {
          total_indicators: threats.length,
          high_risk: threats.filter(t => t.threat_level === 'high').length
        },
        users: {
          total: users.length,
          active: users.filter(u => u.status === 'active').length
        },
        compliance: {
          total_frameworks: compliance.length,
          compliant: compliance.filter(c => c.status === 'compliant').length
        }
      };
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      throw error;
    }
  }
}

export default ComprehensiveSecurityService;
