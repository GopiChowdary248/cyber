import { apiClient } from '../utils/apiClient';

export interface Device {
  id: string;
  name: string;
  type: 'laptop' | 'desktop' | 'mobile' | 'tablet' | 'server' | 'iot';
  mac_address: string;
  ip_address: string;
  os_type: 'windows' | 'macos' | 'linux' | 'android' | 'ios';
  os_version: string;
  user_id: string;
  status: 'active' | 'inactive' | 'quarantined' | 'compromised';
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface DevicePolicy {
  id: string;
  name: string;
  description: string;
  device_types: Device['type'][];
  os_types: Device['os_type'][];
  rules: DeviceRule[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeviceRule {
  id: string;
  rule_type: 'usb_control' | 'network_access' | 'file_access' | 'application_control' | 'encryption';
  action: 'allow' | 'deny' | 'log';
  conditions: DeviceRuleCondition[];
  priority: number;
}

export interface DeviceRuleCondition {
  field: string;
  operator: 'equals' | 'contains' | 'starts_with' | 'ends_with' | 'regex';
  value: string;
}

export interface DeviceActivity {
  id: string;
  device_id: string;
  activity_type: 'login' | 'logout' | 'file_access' | 'network_access' | 'usb_connected' | 'usb_disconnected';
  details: any;
  timestamp: string;
  user_id: string;
  ip_address: string;
}

export interface DeviceCompliance {
  device_id: string;
  policy_compliance: number;
  security_score: number;
  last_scan: string;
  vulnerabilities: string[];
  recommendations: string[];
}

export interface DeviceMetrics {
  total_devices: number;
  devices_by_type: Record<string, number>;
  devices_by_os: Record<string, number>;
  compliance_rate: number;
  quarantined_devices: number;
  compromised_devices: number;
}

class DeviceControlService {
  private baseUrl = '/api/v1/device-control';

  // Device Management
  async getDevices(filters?: {
    type?: Device['type'];
    os_type?: Device['os_type'];
    status?: Device['status'];
    user_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ devices: Device[]; total: number }> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/devices`, { params: filters });
      return response.data;
    } catch (error) {
      console.error('Error fetching devices:', error);
      throw error;
    }
  }

  async getDevice(id: string): Promise<Device> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/devices/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching device:', error);
      throw error;
    }
  }

  async createDevice(device: Omit<Device, 'id' | 'created_at' | 'updated_at'>): Promise<Device> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/devices`, device);
      return response.data;
    } catch (error) {
      console.error('Error creating device:', error);
      throw error;
    }
  }

  async updateDevice(id: string, device: Partial<Device>): Promise<Device> {
    try {
      const response = await apiClient.put(`${this.baseUrl}/devices/${id}`, device);
      return response.data;
    } catch (error) {
      console.error('Error updating device:', error);
      throw error;
    }
  }

  async deleteDevice(id: string): Promise<void> {
    try {
      await apiClient.delete(`${this.baseUrl}/devices/${id}`);
    } catch (error) {
      console.error('Error deleting device:', error);
      throw error;
    }
  }

  // Device Policies
  async getPolicies(): Promise<DevicePolicy[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/policies`);
      return response.data;
    } catch (error) {
      console.error('Error fetching device policies:', error);
      throw error;
    }
  }

  async getPolicy(id: string): Promise<DevicePolicy> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/policies/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching device policy:', error);
      throw error;
    }
  }

  async createPolicy(policy: Omit<DevicePolicy, 'id' | 'created_at' | 'updated_at'>): Promise<DevicePolicy> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/policies`, policy);
      return response.data;
    } catch (error) {
      console.error('Error creating device policy:', error);
      throw error;
    }
  }

  async updatePolicy(id: string, policy: Partial<DevicePolicy>): Promise<DevicePolicy> {
    try {
      const response = await apiClient.put(`${this.baseUrl}/policies/${id}`, policy);
      return response.data;
    } catch (error) {
      console.error('Error updating device policy:', error);
      throw error;
    }
  }

  async deletePolicy(id: string): Promise<void> {
    try {
      await apiClient.delete(`${this.baseUrl}/policies/${id}`);
    } catch (error) {
      console.error('Error deleting device policy:', error);
      throw error;
    }
  }

  // Device Activities
  async getDeviceActivities(deviceId: string, filters?: {
    activity_type?: DeviceActivity['activity_type'];
    start_date?: string;
    end_date?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ activities: DeviceActivity[]; total: number }> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/devices/${deviceId}/activities`, { params: filters });
      return response.data;
    } catch (error) {
      console.error('Error fetching device activities:', error);
      throw error;
    }
  }

  async getAllActivities(filters?: {
    device_id?: string;
    activity_type?: DeviceActivity['activity_type'];
    user_id?: string;
    start_date?: string;
    end_date?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ activities: DeviceActivity[]; total: number }> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/activities`, { params: filters });
      return response.data;
    } catch (error) {
      console.error('Error fetching all activities:', error);
      throw error;
    }
  }

  // Device Compliance
  async getDeviceCompliance(deviceId: string): Promise<DeviceCompliance> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/devices/${deviceId}/compliance`);
      return response.data;
    } catch (error) {
      console.error('Error fetching device compliance:', error);
      throw error;
    }
  }

  async getAllCompliance(): Promise<DeviceCompliance[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/compliance`);
      return response.data;
    } catch (error) {
      console.error('Error fetching all compliance:', error);
      throw error;
    }
  }

  // Device Control Actions
  async quarantineDevice(deviceId: string, reason: string): Promise<Device> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/devices/${deviceId}/quarantine`, { reason });
      return response.data;
    } catch (error) {
      console.error('Error quarantining device:', error);
      throw error;
    }
  }

  async releaseDevice(deviceId: string): Promise<Device> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/devices/${deviceId}/release`);
      return response.data;
    } catch (error) {
      console.error('Error releasing device:', error);
      throw error;
    }
  }

  async scanDevice(deviceId: string): Promise<{ scan_id: string; status: string }> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/devices/${deviceId}/scan`);
      return response.data;
    } catch (error) {
      console.error('Error scanning device:', error);
      throw error;
    }
  }

  async getScanStatus(scanId: string): Promise<{ status: string; progress: number; results?: any }> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/scans/${scanId}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching scan status:', error);
      throw error;
    }
  }

  // USB Control
  async getUSBDevices(deviceId: string): Promise<any[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/devices/${deviceId}/usb-devices`);
      return response.data;
    } catch (error) {
      console.error('Error fetching USB devices:', error);
      throw error;
    }
  }

  async blockUSBDevice(deviceId: string, usbDeviceId: string): Promise<void> {
    try {
      await apiClient.post(`${this.baseUrl}/devices/${deviceId}/usb-devices/${usbDeviceId}/block`);
    } catch (error) {
      console.error('Error blocking USB device:', error);
      throw error;
    }
  }

  async allowUSBDevice(deviceId: string, usbDeviceId: string): Promise<void> {
    try {
      await apiClient.post(`${this.baseUrl}/devices/${deviceId}/usb-devices/${usbDeviceId}/allow`);
    } catch (error) {
      console.error('Error allowing USB device:', error);
      throw error;
    }
  }

  // Network Access Control
  async getNetworkAccess(deviceId: string): Promise<any> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/devices/${deviceId}/network-access`);
      return response.data;
    } catch (error) {
      console.error('Error fetching network access:', error);
      throw error;
    }
  }

  async updateNetworkAccess(deviceId: string, networkAccess: any): Promise<any> {
    try {
      const response = await apiClient.put(`${this.baseUrl}/devices/${deviceId}/network-access`, networkAccess);
      return response.data;
    } catch (error) {
      console.error('Error updating network access:', error);
      throw error;
    }
  }

  // Device Metrics
  async getMetrics(timeRange?: '24h' | '7d' | '30d' | '90d'): Promise<DeviceMetrics> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/metrics`, { 
        params: { time_range: timeRange } 
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching device metrics:', error);
      throw error;
    }
  }

  // Bulk Operations
  async bulkUpdateDevices(deviceIds: string[], updates: Partial<Device>): Promise<Device[]> {
    try {
      const response = await apiClient.patch(`${this.baseUrl}/devices/bulk-update`, {
        device_ids: deviceIds,
        updates
      });
      return response.data;
    } catch (error) {
      console.error('Error bulk updating devices:', error);
      throw error;
    }
  }

  async bulkQuarantineDevices(deviceIds: string[], reason: string): Promise<Device[]> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/devices/bulk-quarantine`, {
        device_ids: deviceIds,
        reason
      });
      return response.data;
    } catch (error) {
      console.error('Error bulk quarantining devices:', error);
      throw error;
    }
  }

  // Export Data
  async exportDeviceData(format: 'json' | 'csv' | 'pdf', filters?: any): Promise<Blob> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/export/devices`, { 
        params: { format, ...filters },
        responseType: 'blob'
      });
      return response.data;
    } catch (error) {
      console.error('Error exporting device data:', error);
      throw error;
    }
  }

  async exportActivityLogs(format: 'json' | 'csv' | 'pdf', filters?: any): Promise<Blob> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/export/activities`, { 
        params: { format, ...filters },
        responseType: 'blob'
      });
      return response.data;
    } catch (error) {
      console.error('Error exporting activity logs:', error);
      throw error;
    }
  }
}

export const deviceControlService = new DeviceControlService();
export default deviceControlService;
