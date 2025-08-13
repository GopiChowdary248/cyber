import { apiClient } from '../utils/apiClient';

export interface Endpoint {
  id: string;
  device_name: string;
  device_type: string;
  vendor: string;
  model: string;
  serial_number: string;
  device_id: string;
  capacity: string;
  file_system: string;
  is_encrypted: boolean;
  is_approved: boolean;
  status: string;
  last_seen: string;
  first_seen: string;
  endpoint_id: string;
  created_at: string;
  updated_at: string;
}

export interface ScanStatus {
  id: string;
  endpoint_id: string;
  scan_type: string;
  scan_path: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  started_at: string;
  completed_at?: string;
  findings_count: number;
  threats_detected: number;
  files_scanned: number;
}

export interface EDRAlert {
  id: string;
  endpoint_id: string;
  alert_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  timestamp: string;
  status: 'new' | 'acknowledged' | 'resolved' | 'false_positive';
  indicators: string[];
  raw_data: any;
}

export interface WhitelistEntry {
  id: string;
  application_path: string;
  application_hash: string;
  reason: string;
  approved_by: string;
  approved_at: string;
  expires_at?: string;
}

export interface ThreatAnalysis {
  total_threats: number;
  critical_threats: number;
  high_threats: number;
  medium_threats: number;
  low_threats: number;
  threats_by_type: Record<string, number>;
  recent_threats: any[];
  threat_trends: any[];
}

export interface EndpointSecuritySummary {
  total_endpoints: number;
  online_endpoints: number;
  offline_endpoints: number;
  quarantined_endpoints: number;
  total_scans: number;
  active_scans: number;
  total_alerts: number;
  unacknowledged_alerts: number;
  risk_score: number;
}

class EndpointAntivirusEdrService {
  private baseUrl = '/api/v1/endpoint-antivirus-edr';

  // Endpoint Management
  async getEndpoints(): Promise<Endpoint[]> {
    const response = await apiClient.get(`${this.baseUrl}/endpoints`);
    return response.data;
  }

  async getEndpointDetails(endpointId: string): Promise<Endpoint> {
    const response = await apiClient.get(`${this.baseUrl}/endpoints/${endpointId}`);
    return response.data;
  }

  async registerEndpoint(endpointData: Partial<Endpoint>): Promise<{ endpoint_id: string; message: string }> {
    const response = await apiClient.post(`${this.baseUrl}/endpoints`, endpointData);
    return response.data;
  }

  async updateEndpointStatus(endpointId: string, status: string): Promise<{ message: string }> {
    const response = await apiClient.put(`${this.baseUrl}/endpoints/${endpointId}/status`, { status });
    return response.data;
  }

  // Antivirus Management
  async startAntivirusScan(
    endpointId: string,
    scanType: string = 'quick',
    scanPath: string = 'C:\\'
  ): Promise<{ scan_id: string; message: string }> {
    const response = await apiClient.post(`${this.baseUrl}/antivirus/scan`, {
      endpoint_id: endpointId,
      scan_type: scanType,
      scan_path: scanPath
    });
    return response.data;
  }

  async getScanStatus(scanId: string): Promise<ScanStatus> {
    const response = await apiClient.get(`${this.baseUrl}/antivirus/scan/${scanId}`);
    return response.data;
  }

  async getEndpointScans(endpointId: string): Promise<ScanStatus[]> {
    const response = await apiClient.get(`${this.baseUrl}/antivirus/endpoint/${endpointId}/scans`);
    return response.data;
  }

  // EDR Management
  async createEDRAlert(endpointId: string, alertData: any): Promise<{ alert_id: string; message: string }> {
    const response = await apiClient.post(`${this.baseUrl}/edr/alerts`, {
      endpoint_id: endpointId,
      alert_data: alertData
    });
    return response.data;
  }

  async getEDRAlerts(endpointId?: string, status?: string): Promise<EDRAlert[]> {
    const params = new URLSearchParams();
    if (endpointId) params.append('endpoint_id', endpointId);
    if (status) params.append('status', status);
    
    const response = await apiClient.get(`${this.baseUrl}/edr/alerts?${params.toString()}`);
    return response.data;
  }

  async updateAlertStatus(alertId: string, status: string): Promise<{ message: string }> {
    const response = await apiClient.put(`${this.baseUrl}/edr/alerts/${alertId}/status`, { status });
    return response.data;
  }

  // Whitelist Management
  async addWhitelistEntry(entryData: Partial<WhitelistEntry>): Promise<{ entry_id: string; message: string }> {
    const response = await apiClient.post(`${this.baseUrl}/whitelist`, entryData);
    return response.data;
  }

  async removeWhitelistEntry(entryId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`${this.baseUrl}/whitelist/${entryId}`);
    return response.data;
  }

  async getWhitelistEntries(): Promise<WhitelistEntry[]> {
    const response = await apiClient.get(`${this.baseUrl}/whitelist`);
    return response.data;
  }

  async checkApplicationWhitelist(appPath: string, appHash: string): Promise<any> {
    const response = await apiClient.post(`${this.baseUrl}/whitelist/check`, {
      app_path: appPath,
      app_hash: appHash
    });
    return response.data;
  }

  // Analytics and Reporting
  async getEndpointSecuritySummary(): Promise<EndpointSecuritySummary> {
    const response = await apiClient.get(`${this.baseUrl}/summary`);
    return response.data;
  }

  async getThreatAnalysis(days: number = 7): Promise<ThreatAnalysis> {
    const response = await apiClient.get(`${this.baseUrl}/threat-analysis?days=${days}`);
    return response.data;
  }

  // Bulk Operations
  async startBulkScan(endpointIds: string[], scanType: string = 'quick'): Promise<{ scan_ids: string[]; message: string }> {
    const response = await apiClient.post(`${this.baseUrl}/bulk/scan`, {
      endpoint_ids: endpointIds,
      scan_type: scanType
    });
    return response.data;
  }

  async quarantineEndpoints(endpointIds: string[]): Promise<{ message: string; quarantined_count: number }> {
    const response = await apiClient.post(`${this.baseUrl}/bulk/quarantine`, {
      endpoint_ids: endpointIds
    });
    return response.data;
  }

  // Health Check
  async healthCheck(): Promise<{ status: string; message: string; timestamp: string }> {
    const response = await apiClient.get(`${this.baseUrl}/health`);
    return response.data;
  }
}

export const endpointAntivirusEdrService = new EndpointAntivirusEdrService();
