import { apiClient } from '../utils/apiClient';

/**
 * Comprehensive API Integration Service
 * Connects all frontend services with backend endpoints
 */

export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  timestamp: string;
}

export interface PaginatedResponse<T> extends APIResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export class APIIntegrationService {
  private static instance: APIIntegrationService;
  
  private constructor() {}
  
  static getInstance(): APIIntegrationService {
    if (!APIIntegrationService.instance) {
      APIIntegrationService.instance = new APIIntegrationService();
    }
    return APIIntegrationService.instance;
  }

  // Health Check
  async checkHealth(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/health');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Health check failed',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Authentication Endpoints
  async login(credentials: { username: string; password: string }): Promise<APIResponse> {
    try {
      const response = await apiClient.post('/api/v1/auth/login', credentials);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Login failed',
        timestamp: new Date().toISOString()
      };
    }
  }

  async register(userData: any): Promise<APIResponse> {
    try {
      const response = await apiClient.post('/api/v1/auth/register', userData);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Registration failed',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getCurrentUser(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/auth/me');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get current user',
        timestamp: new Date().toISOString()
      };
    }
  }

  // User Management Endpoints
  async getUsers(params?: { page?: number; limit?: number; search?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/users', { params });
      return {
        success: true,
        data: response.data.users || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get users',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  async getUserById(id: string): Promise<APIResponse> {
    try {
      const response = await apiClient.get(`/api/v1/users/${id}`);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get user',
        timestamp: new Date().toISOString()
      };
    }
  }

  async updateUser(id: string, userData: any): Promise<APIResponse> {
    try {
      const response = await apiClient.put(`/api/v1/users/${id}`, userData);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to update user',
        timestamp: new Date().toISOString()
      };
    }
  }

  async deleteUser(id: string): Promise<APIResponse> {
    try {
      const response = await apiClient.delete(`/api/v1/users/${id}`);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to delete user',
        timestamp: new Date().toISOString()
      };
    }
  }

  // IAM Endpoints
  async getIAMUsers(params?: { page?: number; limit?: number; role?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/iam/users', { params });
      return {
        success: true,
        data: response.data.users || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get IAM users',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  async createIAMUser(userData: any): Promise<APIResponse> {
    try {
      const response = await apiClient.post('/api/v1/iam/users', userData);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to create IAM user',
        timestamp: new Date().toISOString()
      };
    }
  }

  // DAST Endpoints
  async getDASTProjects(params?: { page?: number; limit?: number; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/dast/projects', { params });
      return {
        success: true,
        data: response.data.projects || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get DAST projects',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  async createDASTProject(projectData: any): Promise<APIResponse> {
    try {
      const response = await apiClient.post('/api/v1/dast/projects', projectData);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to create DAST project',
        timestamp: new Date().toISOString()
      };
    }
  }

  async startDASTScan(projectId: string, scanConfig: any): Promise<APIResponse> {
    try {
      const response = await apiClient.post(`/api/v1/dast/projects/${projectId}/scans`, scanConfig);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to start DAST scan',
        timestamp: new Date().toISOString()
      };
    }
  }

  // RASP Endpoints
  async getRASPProjects(params?: { page?: number; limit?: number; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/rasp/projects', { params });
      return {
        success: true,
        data: response.data.projects || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get RASP projects',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  async createRASPProject(projectData: any): Promise<APIResponse> {
    try {
      const response = await apiClient.post('/api/v1/rasp/projects', projectData);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to create RASP project',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Cloud Security Endpoints
  async getCloudSecurityStatus(provider?: string): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/cloud-security/status', { params: { provider } });
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get cloud security status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getCloudMisconfigurations(provider?: string, severity?: string): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/cloud-security/misconfigurations', { 
        params: { provider, severity } 
      });
      return {
        success: true,
        data: response.data.misconfigurations || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get cloud misconfigurations',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Network Security Endpoints
  async getNetworkSecurityStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/network-security/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get network security status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getNetworkThreats(params?: { severity?: string; type?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/network-security/threats', { params });
      return {
        success: true,
        data: response.data.threats || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get network threats',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Data Security Endpoints
  async getDataSecurityStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/data-security/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get data security status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getDataBreaches(params?: { severity?: string; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/data-security/breaches', { params });
      return {
        success: true,
        data: response.data.breaches || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get data breaches',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Endpoint Security Endpoints
  async getEndpointSecurityStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/endpoint-antivirus-edr/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get endpoint security status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getEndpointThreats(params?: { severity?: string; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/endpoint-antivirus-edr/threats', { params });
      return {
        success: true,
        data: response.data.threats || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get endpoint threats',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Device Control Endpoints
  async getDeviceControlStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/device-control/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get device control status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getDevicePolicies(params?: { type?: string; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/device-control/policies', { params });
      return {
        success: true,
        data: response.data.policies || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get device policies',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Data Protection Endpoints
  async getDataProtectionStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/data-protection/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get data protection status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getDataProtectionPolicies(params?: { type?: string; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/data-protection/policies', { params });
      return {
        success: true,
        data: response.data.policies || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get data protection policies',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Security Operations Endpoints
  async getSecurityOperationsStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/security/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get security operations status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getSecurityIncidents(params?: { severity?: string; status?: string }): Promise<PaginatedResponse<any>> {
    try {
      const response = await apiClient.get('/api/v1/security/incidents', { params });
      return {
        success: true,
        data: response.data.incidents || response.data,
        pagination: response.data.pagination || { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get security incidents',
        pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        timestamp: new Date().toISOString()
      };
    }
  }

  // Monitoring & SIEM/SOAR Endpoints
  async getMonitoringStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/monitoring/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get monitoring status',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getSIEMSOARStatus(): Promise<APIResponse> {
    try {
      const response = await apiClient.get('/api/v1/siem-soar/status');
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get SIEM/SOAR status',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Generic CRUD operations
  async createResource(endpoint: string, data: any): Promise<APIResponse> {
    try {
      const response = await apiClient.post(endpoint, data);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to create resource',
        timestamp: new Date().toISOString()
      };
    }
  }

  async updateResource(endpoint: string, data: any): Promise<APIResponse> {
    try {
      const response = await apiClient.put(endpoint, data);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to update resource',
        timestamp: new Date().toISOString()
      };
    }
  }

  async deleteResource(endpoint: string): Promise<APIResponse> {
    try {
      const response = await apiClient.delete(endpoint);
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to delete resource',
        timestamp: new Date().toISOString()
      };
    }
  }

  async getResource(endpoint: string, params?: any): Promise<APIResponse> {
    try {
      const response = await apiClient.get(endpoint, { params });
      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get resource',
        timestamp: new Date().toISOString()
      };
    }
  }
}

export const apiIntegrationService = APIIntegrationService.getInstance();
export default apiIntegrationService;
