import { apiClient } from '../utils/apiClient';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  source_ip?: string;
  destination_ip?: string;
  user_id?: string;
  hostname?: string;
  raw_data: any;
  normalized_data: any;
  tags: string[];
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
}

export interface SecurityAlert {
  id: string;
  event_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'closed';
  assigned_to?: number;
  created_at: string;
  updated_at: string;
  tags: string[];
  false_positive: boolean;
  escalation_level: number;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  rule_type: 'correlation' | 'threshold' | 'anomaly' | 'ml_based';
  enabled: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  conditions: any;
  actions: string[];
  created_at: string;
  updated_at: string;
  last_triggered?: string;
  trigger_count: number;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger_conditions: any;
  steps: PlaybookStep[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  last_executed?: string;
  execution_count: number;
}

export interface PlaybookStep {
  id: string;
  name: string;
  action: string;
  parameters: any;
  order: number;
  timeout?: number;
  retry_count?: number;
  on_failure?: 'continue' | 'stop' | 'retry';
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  trigger_event_id: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  started_at: string;
  completed_at?: string;
  steps_executed: PlaybookStepExecution[];
  error_message?: string;
}

export interface PlaybookStepExecution {
  step_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  result?: any;
  error_message?: string;
}

export interface SecurityDashboard {
  id: string;
  name: string;
  description: string;
  widgets: DashboardWidget[];
  layout: any;
  created_at: string;
  updated_at: string;
  is_default: boolean;
}

export interface DashboardWidget {
  id: string;
  type: string;
  title: string;
  configuration: any;
  position: { x: number; y: number; width: number; height: number };
}

export interface SIEMSoarMetrics {
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  active_playbooks: number;
  events_per_second: number;
  alert_response_time: number;
  false_positive_rate: number;
  top_event_sources: string[];
  top_alert_types: string[];
}

class SIEMSoarService {
  // Get security events
  async getSecurityEvents(
    skip: number = 0,
    limit: number = 100,
    source?: string,
    event_type?: string,
    severity?: string,
    status?: string,
    date_from?: string,
    date_to?: string
  ): Promise<{ events: SecurityEvent[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (source) params.append('source', source);
    if (event_type) params.append('event_type', event_type);
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (date_from) params.append('date_from', date_from);
    if (date_to) params.append('date_to', date_to);

    const response = await apiClient.get(`/siem-soar/events?${params.toString()}`);
    return response.data;
  }

  // Get security event by ID
  async getSecurityEvent(eventId: string): Promise<SecurityEvent> {
    const response = await apiClient.get(`/siem-soar/events/${eventId}`);
    return response.data;
  }

  // Update event status
  async updateEventStatus(eventId: string, status: string): Promise<SecurityEvent> {
    const response = await apiClient.put(`/siem-soar/events/${eventId}/status`, { status });
    return response.data;
  }

  // Get security alerts
  async getSecurityAlerts(
    skip: number = 0,
    limit: number = 100,
    severity?: string,
    status?: string,
    assigned_to?: number
  ): Promise<{ alerts: SecurityAlert[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (assigned_to) params.append('assigned_to', assigned_to.toString());

    const response = await apiClient.get(`/siem-soar/alerts?${params.toString()}`);
    return response.data;
  }

  // Get security alert by ID
  async getSecurityAlert(alertId: string): Promise<SecurityAlert> {
    const response = await apiClient.get(`/siem-soar/alerts/${alertId}`);
    return response.data;
  }

  // Update alert status
  async updateAlertStatus(alertId: string, status: string, assigned_to?: number): Promise<SecurityAlert> {
    const response = await apiClient.put(`/siem-soar/alerts/${alertId}/status`, { status, assigned_to });
    return response.data;
  }

  // Mark alert as false positive
  async markAlertFalsePositive(alertId: string, reason: string): Promise<SecurityAlert> {
    const response = await apiClient.put(`/siem-soar/alerts/${alertId}/false-positive`, { reason });
    return response.data;
  }

  // Get detection rules
  async getDetectionRules(
    skip: number = 0,
    limit: number = 100,
    rule_type?: string,
    enabled?: boolean
  ): Promise<{ rules: DetectionRule[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (rule_type) params.append('rule_type', rule_type);
    if (enabled !== undefined) params.append('enabled', enabled.toString());

    const response = await apiClient.get(`/siem-soar/rules?${params.toString()}`);
    return response.data;
  }

  // Get detection rule by ID
  async getDetectionRule(ruleId: string): Promise<DetectionRule> {
    const response = await apiClient.get(`/siem-soar/rules/${ruleId}`);
    return response.data;
  }

  // Create detection rule
  async createDetectionRule(ruleData: Partial<DetectionRule>): Promise<DetectionRule> {
    const response = await apiClient.post('/siem-soar/rules', ruleData);
    return response.data;
  }

  // Update detection rule
  async updateDetectionRule(ruleId: string, updateData: Partial<DetectionRule>): Promise<DetectionRule> {
    const response = await apiClient.put(`/siem-soar/rules/${ruleId}`, updateData);
    return response.data;
  }

  // Delete detection rule
  async deleteDetectionRule(ruleId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/siem-soar/rules/${ruleId}`);
    return response.data;
  }

  // Enable/disable detection rule
  async toggleDetectionRule(ruleId: string, enabled: boolean): Promise<DetectionRule> {
    const response = await apiClient.put(`/siem-soar/rules/${ruleId}/toggle`, { enabled });
    return response.data;
  }

  // Get playbooks
  async getPlaybooks(
    skip: number = 0,
    limit: number = 100,
    enabled?: boolean
  ): Promise<{ playbooks: Playbook[]; total: number }> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (enabled !== undefined) params.append('enabled', enabled.toString());

    const response = await apiClient.get(`/siem-soar/playbooks?${params.toString()}`);
    return response.data;
  }

  // Get playbook by ID
  async getPlaybook(playbookId: string): Promise<Playbook> {
    const response = await apiClient.get(`/siem-soar/playbooks/${playbookId}`);
    return response.data;
  }

  // Create playbook
  async createPlaybook(playbookData: Partial<Playbook>): Promise<Playbook> {
    const response = await apiClient.post('/siem-soar/playbooks', playbookData);
    return response.data;
  }

  // Update playbook
  async updatePlaybook(playbookId: string, updateData: Partial<Playbook>): Promise<Playbook> {
    const response = await apiClient.put(`/siem-soar/playbooks/${playbookId}`, updateData);
    return response.data;
  }

  // Delete playbook
  async deletePlaybook(playbookId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/siem-soar/playbooks/${playbookId}`);
    return response.data;
  }

  // Execute playbook manually
  async executePlaybook(playbookId: string, triggerEventId: string): Promise<PlaybookExecution> {
    const response = await apiClient.post(`/siem-soar/playbooks/${playbookId}/execute`, {
      trigger_event_id: triggerEventId
    });
    return response.data;
  }

  // Get playbook executions
  async getPlaybookExecutions(
    playbookId?: string,
    status?: string,
    skip: number = 0,
    limit: number = 100
  ): Promise<{ executions: PlaybookExecution[]; total: number }> {
    const params = new URLSearchParams();
    if (playbookId) params.append('playbook_id', playbookId);
    if (status) params.append('status', status);
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());

    const response = await apiClient.get(`/siem-soar/playbook-executions?${params.toString()}`);
    return response.data;
  }

  // Get playbook execution by ID
  async getPlaybookExecution(executionId: string): Promise<PlaybookExecution> {
    const response = await apiClient.get(`/siem-soar/playbook-executions/${executionId}`);
    return response.data;
  }

  // Cancel playbook execution
  async cancelPlaybookExecution(executionId: string): Promise<{ message: string }> {
    const response = await apiClient.post(`/siem-soar/playbook-executions/${executionId}/cancel`);
    return response.data;
  }

  // Get security dashboards
  async getSecurityDashboards(): Promise<SecurityDashboard[]> {
    const response = await apiClient.get('/siem-soar/dashboards');
    return response.data;
  }

  // Get security dashboard by ID
  async getSecurityDashboard(dashboardId: string): Promise<SecurityDashboard> {
    const response = await apiClient.get(`/siem-soar/dashboards/${dashboardId}`);
    return response.data;
  }

  // Create security dashboard
  async createSecurityDashboard(dashboardData: Partial<SecurityDashboard>): Promise<SecurityDashboard> {
    const response = await apiClient.post('/siem-soar/dashboards', dashboardData);
    return response.data;
  }

  // Update security dashboard
  async updateSecurityDashboard(
    dashboardId: string,
    updateData: Partial<SecurityDashboard>
  ): Promise<SecurityDashboard> {
    const response = await apiClient.put(`/siem-soar/dashboards/${dashboardId}`, updateData);
    return response.data;
  }

  // Delete security dashboard
  async deleteSecurityDashboard(dashboardId: string): Promise<{ message: string }> {
    const response = await apiClient.delete(`/siem-soar/dashboards/${dashboardId}`);
    return response.data;
  }

  // Get SIEM/SOAR metrics
  async getSIEMSoarMetrics(): Promise<SIEMSoarMetrics> {
    const response = await apiClient.get('/siem-soar/metrics');
    return response.data;
  }

  // Search security data
  async searchSecurityData(
    query: string,
    dataType: 'events' | 'alerts' | 'all',
    filters?: any
  ): Promise<any> {
    const response = await apiClient.post('/siem-soar/search', {
      query,
      data_type: dataType,
      filters
    });
    return response.data;
  }

  // Export security data
  async exportSecurityData(
    dataType: 'events' | 'alerts' | 'rules' | 'playbooks',
    format: 'csv' | 'json' | 'xml',
    filters?: any
  ): Promise<{ download_url: string }> {
    const response = await apiClient.post('/siem-soar/export', {
      data_type: dataType,
      format,
      filters
    });
    return response.data;
  }
}

export const siemSoarService = new SIEMSoarService();
export default siemSoarService;
