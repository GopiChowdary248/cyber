import { apiClient } from '../utils/apiClient';

export interface FirewallRule {
  id: number;
  name: string;
  description?: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  action: 'allow' | 'deny' | 'log';
  priority: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface FirewallRuleCreate {
  name: string;
  description?: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  action: 'allow' | 'deny' | 'log';
  priority?: number;
  is_active?: boolean;
}

export interface FirewallRuleUpdate {
  name?: string;
  description?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  action?: 'allow' | 'deny' | 'log';
  priority?: number;
  is_active?: boolean;
}

export interface NetworkSegment {
  id: number;
  name: string;
  description?: string;
  cidr: string;
  vlan_id?: number;
  security_level: 'low' | 'medium' | 'high' | 'critical';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface NetworkSegmentCreate {
  name: string;
  description?: string;
  cidr: string;
  vlan_id?: number;
  security_level: 'low' | 'medium' | 'high' | 'critical';
  is_active?: boolean;
}

export interface NetworkSegmentUpdate {
  name?: string;
  description?: string;
  cidr?: string;
  vlan_id?: number;
  security_level?: 'low' | 'medium' | 'high' | 'critical';
  is_active?: boolean;
}

export interface IDSAlert {
  id: number;
  rule_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source_ip: string;
  destination_ip: string;
  protocol: string;
  signature: string;
  description: string;
  timestamp: string;
  is_resolved: boolean;
  resolution_notes?: string;
  created_at: string;
  updated_at: string;
}

export interface IDSAlertUpdate {
  is_resolved?: boolean;
  resolution_notes?: string;
}

export interface NetworkScan {
  id: number;
  name: string;
  description?: string;
  target_ips: string[];
  scan_type: 'vulnerability' | 'port' | 'service' | 'comprehensive';
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  results?: Record<string, any>;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface NetworkScanCreate {
  name: string;
  description?: string;
  target_ips: string[];
  scan_type: 'vulnerability' | 'port' | 'service' | 'comprehensive';
}

export interface NetworkTraffic {
  id: number;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  timestamp: string;
  connection_duration: number;
  is_encrypted: boolean;
  application?: string;
  user_id?: number;
}

export interface NetworkDevice {
  id: number;
  name: string;
  ip_address: string;
  mac_address: string;
  device_type: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  is_managed: boolean;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface NetworkDeviceCreate {
  name: string;
  ip_address: string;
  mac_address: string;
  device_type: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  is_managed?: boolean;
}

export interface NetworkDeviceUpdate {
  name?: string;
  ip_address?: string;
  mac_address?: string;
  device_type?: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  is_managed?: boolean;
}

export interface NetworkSecurityStats {
  total_firewall_rules: number;
  active_firewall_rules: number;
  total_network_segments: number;
  active_network_segments: number;
  total_ids_alerts: number;
  unresolved_ids_alerts: number;
  total_network_scans: number;
  running_network_scans: number;
  total_network_devices: number;
  managed_network_devices: number;
  traffic_summary: Record<string, any>;
  security_incidents: Record<string, any>[];
}

class NetworkSecurityService {
  // Firewall rule management
  async getFirewallRules(): Promise<FirewallRule[]> {
    const response = await apiClient.get('/network-security/firewall-rules');
    return response.data;
  }

  async getFirewallRule(ruleId: number): Promise<FirewallRule> {
    const response = await apiClient.get(`/network-security/firewall-rules/${ruleId}`);
    return response.data;
  }

  async createFirewallRule(ruleData: FirewallRuleCreate): Promise<FirewallRule> {
    const response = await apiClient.post('/network-security/firewall-rules', ruleData);
    return response.data;
  }

  async updateFirewallRule(ruleId: number, ruleUpdate: FirewallRuleUpdate): Promise<FirewallRule> {
    const response = await apiClient.put(`/network-security/firewall-rules/${ruleId}`, ruleUpdate);
    return response.data;
  }

  async deleteFirewallRule(ruleId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/network-security/firewall-rules/${ruleId}`);
    return response.data;
  }

  async activateFirewallRule(ruleId: number): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/firewall-rules/${ruleId}/activate`);
    return response.data;
  }

  async deactivateFirewallRule(ruleId: number): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/firewall-rules/${ruleId}/deactivate`);
    return response.data;
  }

  // Network segment management
  async getNetworkSegments(): Promise<NetworkSegment[]> {
    const response = await apiClient.get('/network-security/network-segments');
    return response.data;
  }

  async getNetworkSegment(segmentId: number): Promise<NetworkSegment> {
    const response = await apiClient.get(`/network-security/network-segments/${segmentId}`);
    return response.data;
  }

  async createNetworkSegment(segmentData: NetworkSegmentCreate): Promise<NetworkSegment> {
    const response = await apiClient.post('/network-security/network-segments', segmentData);
    return response.data;
  }

  async updateNetworkSegment(segmentId: number, segmentUpdate: NetworkSegmentUpdate): Promise<NetworkSegment> {
    const response = await apiClient.put(`/network-security/network-segments/${segmentId}`, segmentUpdate);
    return response.data;
  }

  async deleteNetworkSegment(segmentId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/network-security/network-segments/${segmentId}`);
    return response.data;
  }

  // IDS alert management
  async getIDSAlerts(
    skip: number = 0,
    limit: number = 100,
    severity?: string,
    isResolved?: boolean,
    dateFrom?: string,
    dateTo?: string
  ): Promise<{ alerts: IDSAlert[]; total: number }> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (severity) params.append('severity', severity);
    if (isResolved !== undefined) params.append('is_resolved', isResolved.toString());
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`/network-security/ids-alerts?${params.toString()}`);
    return response.data;
  }

  async getIDSAlert(alertId: number): Promise<IDSAlert> {
    const response = await apiClient.get(`/network-security/ids-alerts/${alertId}`);
    return response.data;
  }

  async updateIDSAlert(alertId: number, alertUpdate: IDSAlertUpdate): Promise<IDSAlert> {
    const response = await apiClient.put(`/network-security/ids-alerts/${alertId}`, alertUpdate);
    return response.data;
  }

  async resolveIDSAlert(alertId: number, resolutionNotes?: string): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/ids-alerts/${alertId}/resolve`, {
      resolution_notes: resolutionNotes
    });
    return response.data;
  }

  async bulkResolveIDSAlerts(alertIds: number[], resolutionNotes?: string): Promise<{ message: string; resolved_count: number }> {
    const response = await apiClient.put('/network-security/ids-alerts/bulk-resolve', {
      alert_ids: alertIds,
      resolution_notes: resolutionNotes
    });
    return response.data;
  }

  // Network scanning
  async getNetworkScans(
    skip: number = 0,
    limit: number = 100,
    status?: string,
    scanType?: string
  ): Promise<{ scans: NetworkScan[]; total: number }> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (status) params.append('status', status);
    if (scanType) params.append('scan_type', scanType);

    const response = await apiClient.get(`/network-security/network-scans?${params.toString()}`);
    return response.data;
  }

  async getNetworkScan(scanId: number): Promise<NetworkScan> {
    const response = await apiClient.get(`/network-security/network-scans/${scanId}`);
    return response.data;
  }

  async createNetworkScan(scanData: NetworkScanCreate): Promise<NetworkScan> {
    const response = await apiClient.post('/network-security/network-scans', scanData);
    return response.data;
  }

  async startNetworkScan(scanId: number): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/network-scans/${scanId}/start`);
    return response.data;
  }

  async stopNetworkScan(scanId: number): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/network-scans/${scanId}/stop`);
    return response.data;
  }

  async deleteNetworkScan(scanId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/network-security/network-scans/${scanId}`);
    return response.data;
  }

  // Network traffic monitoring
  async getNetworkTraffic(
    skip: number = 0,
    limit: number = 100,
    sourceIp?: string,
    destinationIp?: string,
    protocol?: string,
    dateFrom?: string,
    dateTo?: string
  ): Promise<{ traffic: NetworkTraffic[]; total: number }> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (sourceIp) params.append('source_ip', sourceIp);
    if (destinationIp) params.append('destination_ip', destinationIp);
    if (protocol) params.append('protocol', protocol);
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`/network-security/network-traffic?${params.toString()}`);
    return response.data;
  }

  async getNetworkTrafficStats(
    dateFrom?: string,
    dateTo?: string,
    groupBy?: 'hour' | 'day' | 'week' | 'month'
  ): Promise<{ stats: Record<string, any>[] }> {
    const params = new URLSearchParams();
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (groupBy) params.append('group_by', groupBy);

    const response = await apiClient.get(`/network-security/network-traffic/stats?${params.toString()}`);
    return response.data;
  }

  // Network device management
  async getNetworkDevices(
    skip: number = 0,
    limit: number = 100,
    deviceType?: string,
    isManaged?: boolean
  ): Promise<{ devices: NetworkDevice[]; total: number }> {
    const params = new URLSearchParams();
    params.append('skip', skip.toString());
    params.append('limit', limit.toString());
    
    if (deviceType) params.append('device_type', deviceType);
    if (isManaged !== undefined) params.append('is_managed', isManaged.toString());

    const response = await apiClient.get(`/network-security/network-devices?${params.toString()}`);
    return response.data;
  }

  async getNetworkDevice(deviceId: number): Promise<NetworkDevice> {
    const response = await apiClient.get(`/network-security/network-devices/${deviceId}`);
    return response.data;
  }

  async createNetworkDevice(deviceData: NetworkDeviceCreate): Promise<NetworkDevice> {
    const response = await apiClient.post('/network-security/network-devices', deviceData);
    return response.data;
  }

  async updateNetworkDevice(deviceId: number, deviceUpdate: NetworkDeviceUpdate): Promise<NetworkDevice> {
    const response = await apiClient.put(`/network-security/network-devices/${deviceId}`, deviceUpdate);
    return response.data;
  }

  async deleteNetworkDevice(deviceId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/network-security/network-devices/${deviceId}`);
    return response.data;
  }

  // Network security policies
  async getNetworkSecurityPolicies(): Promise<{ policies: Record<string, any>[] }> {
    const response = await apiClient.get('/network-security/policies');
    return response.data;
  }

  async updateNetworkSecurityPolicy(
    policyType: string,
    policyData: Record<string, any>
  ): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/policies/${policyType}`, policyData);
    return response.data;
  }

  // Threat intelligence integration
  async getThreatIntelligence(
    ipAddress?: string,
    domain?: string,
    hash?: string
  ): Promise<{ threats: Record<string, any>[] }> {
    const params = new URLSearchParams();
    if (ipAddress) params.append('ip_address', ipAddress);
    if (domain) params.append('domain', domain);
    if (hash) params.append('hash', hash);

    const response = await apiClient.get(`/network-security/threat-intelligence?${params.toString()}`);
    return response.data;
  }

  async submitThreatIndicator(
    indicator: string,
    indicatorType: 'ip' | 'domain' | 'url' | 'hash',
    threatLevel: 'low' | 'medium' | 'high' | 'critical',
    description?: string
  ): Promise<{ message: string }> {
    const response = await apiClient.post('/network-security/threat-indicators', {
      indicator,
      indicator_type: indicatorType,
      threat_level: threatLevel,
      description
    });
    return response.data;
  }

  // Network security monitoring
  async getNetworkSecurityStatus(): Promise<{ status: Record<string, any>; alerts: Record<string, any>[] }> {
    const response = await apiClient.get('/network-security/status');
    return response.data;
  }

  async getNetworkSecurityMetrics(
    metricType: string,
    dateFrom?: string,
    dateTo?: string
  ): Promise<{ metrics: Record<string, any>[] }> {
    const params = new URLSearchParams();
    params.append('metric_type', metricType);
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`/network-security/metrics?${params.toString()}`);
    return response.data;
  }

  // Statistics and reporting
  async getNetworkSecurityStats(): Promise<NetworkSecurityStats> {
    const response = await apiClient.get('/network-security/stats');
    return response.data;
  }

  async exportNetworkSecurityReport(
    reportType: string,
    format: 'csv' | 'json' | 'xlsx' = 'csv',
    dateFrom?: string,
    dateTo?: string
  ): Promise<Blob> {
    const params = new URLSearchParams();
    params.append('report_type', reportType);
    params.append('format', format);
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`/network-security/reports/export?${params.toString()}`, {
      responseType: 'blob'
    });
    return response.data;
  }

  // Network security automation
  async createAutomatedResponse(
    triggerType: string,
    conditions: Record<string, any>,
    actions: Record<string, any>[]
  ): Promise<{ message: string; response_id: number }> {
    const response = await apiClient.post('/network-security/automated-responses', {
      trigger_type: triggerType,
      conditions,
      actions
    });
    return response.data;
  }

  async getAutomatedResponses(): Promise<{ responses: Record<string, any>[] }> {
    const response = await apiClient.get('/network-security/automated-responses');
    return response.data;
  }

  async updateAutomatedResponse(
    responseId: number,
    updates: Record<string, any>
  ): Promise<{ message: string }> {
    const response = await apiClient.put(`/network-security/automated-responses/${responseId}`, updates);
    return response.data;
  }

  async deleteAutomatedResponse(responseId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/network-security/automated-responses/${responseId}`);
    return response.data;
  }
}

export const networkSecurityService = new NetworkSecurityService();
export default networkSecurityService;
