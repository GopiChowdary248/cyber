import { apiClient } from '../utils/apiClient';

export interface LogEntry {
  id: string;
  timestamp: string;
  source: string;
  level: 'debug' | 'info' | 'warning' | 'error' | 'critical';
  message: string;
  details: Record<string, any>;
  correlation_id?: string;
  user_id?: string;
  ip_address?: string;
  session_id?: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  description: string;
  affected_assets: string[];
  indicators: string[];
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  assigned_to?: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface Alert {
  id: string;
  timestamp: string;
  alert_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  title: string;
  description: string;
  affected_assets: string[];
  status: 'active' | 'acknowledged' | 'resolved' | 'suppressed';
  assigned_to?: string;
  escalation_level: number;
  auto_close: boolean;
  metadata: Record<string, any>;
}

export interface Incident {
  id: string;
  incident_number: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  category: string;
  subcategory: string;
  affected_assets: string[];
  assigned_team: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  sla_target?: string;
  sla_breach: boolean;
  tags: string[];
  playbook_id?: string;
  timeline: IncidentTimelineEntry[];
}

export interface IncidentTimelineEntry {
  id: string;
  timestamp: string;
  action: string;
  description: string;
  user: string;
  details?: Record<string, any>;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  severity_levels: string[];
  steps: PlaybookStep[];
  estimated_duration: string;
  required_skills: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PlaybookStep {
  id: string;
  order: number;
  title: string;
  description: string;
  action_type: string;
  parameters: Record<string, any>;
  expected_outcome: string;
  timeout_minutes: number;
  is_manual: boolean;
  dependencies: string[];
}

export interface AutomationRule {
  id: string;
  name: string;
  description: string;
  trigger_conditions: TriggerCondition[];
  actions: AutomationAction[];
  is_active: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
}

export interface TriggerCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than';
  value: any;
  logical_operator?: 'AND' | 'OR';
}

export interface AutomationAction {
  id: string;
  action_type: string;
  parameters: Record<string, any>;
  order: number;
  timeout_seconds?: number;
  retry_count?: number;
}

export interface ThreatIntelligence {
  id: string;
  indicator: string;
  indicator_type: string;
  threat_type: string;
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface Dashboard {
  id: string;
  name: string;
  description: string;
  widgets: DashboardWidget[];
  layout: any;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface DashboardWidget {
  id: string;
  type: string;
  title: string;
  config: Record<string, any>;
  position: { x: number; y: number; w: number; h: number };
}

export interface MetricsData {
  metric_name: string;
  values: Array<{ timestamp: string; value: number }>;
  unit: string;
  trend: 'up' | 'down' | 'stable';
}

class MonitoringSiemSoarService {
  private baseUrl = '/api/v1/monitoring-siem-soar';

  // Log Management
  async getLogs(
    startTime?: string,
    endTime?: string,
    level?: string,
    source?: string,
    limit: number = 100
  ): Promise<LogEntry[]> {
    const params = new URLSearchParams();
    if (startTime) params.append('start_time', startTime);
    if (endTime) params.append('end_time', endTime);
    if (level) params.append('level', level);
    if (source) params.append('source', source);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/logs?${params.toString()}`);
    return response.data;
  }

  async searchLogs(query: string, filters?: Record<string, any>): Promise<LogEntry[]> {
    const response = await apiClient.post(`${this.baseUrl}/logs/search`, {
      query,
      filters
    });
    return response.data;
  }

  // Security Events
  async getSecurityEvents(
    severity?: string,
    status?: string,
    eventType?: string,
    limit: number = 100
  ): Promise<SecurityEvent[]> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (eventType) params.append('event_type', eventType);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/security-events?${params.toString()}`);
    return response.data;
  }

  async updateSecurityEventStatus(eventId: string, status: string, notes?: string): Promise<{
    message: string;
    event_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/security-events/${eventId}`, {
      status,
      notes
    });
    return response.data;
  }

  // Alert Management
  async getAlerts(
    severity?: string,
    status?: string,
    alertType?: string,
    limit: number = 100
  ): Promise<Alert[]> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (alertType) params.append('alert_type', alertType);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/alerts?${params.toString()}`);
    return response.data;
  }

  async acknowledgeAlert(alertId: string, userId: string, notes?: string): Promise<{
    message: string;
    alert_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/alerts/${alertId}/acknowledge`, {
      user_id: userId,
      notes
    });
    return response.data;
  }

  async resolveAlert(alertId: string, userId: string, resolution: string): Promise<{
    message: string;
    alert_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/alerts/${alertId}/resolve`, {
      user_id: userId,
      resolution
    });
    return response.data;
  }

  // Incident Management
  async getIncidents(
    status?: string,
    severity?: string,
    priority?: string,
    limit: number = 100
  ): Promise<Incident[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (priority) params.append('priority', priority);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/incidents?${params.toString()}`);
    return response.data;
  }

  async createIncident(incidentData: Partial<Incident>): Promise<{
    message: string;
    incident_id: string;
    incident_number: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/incidents`, incidentData);
    return response.data;
  }

  async updateIncident(incidentId: string, updateData: Partial<Incident>): Promise<{
    message: string;
    incident_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/incidents/${incidentId}`, updateData);
    return response.data;
  }

  async addIncidentTimelineEntry(
    incidentId: string,
    entry: Omit<IncidentTimelineEntry, 'id'>
  ): Promise<{
    message: string;
    entry_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/incidents/${incidentId}/timeline`, entry);
    return response.data;
  }

  // Playbook Management
  async getPlaybooks(category?: string, isActive?: boolean): Promise<Playbook[]> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (isActive !== undefined) params.append('is_active', isActive.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/playbooks?${params.toString()}`);
    return response.data;
  }

  async executePlaybook(
    playbookId: string,
    incidentId: string,
    parameters?: Record<string, any>
  ): Promise<{
    message: string;
    execution_id: string;
    status: string;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/playbooks/${playbookId}/execute`, {
      incident_id: incidentId,
      parameters
    });
    return response.data;
  }

  // Automation Rules
  async getAutomationRules(isActive?: boolean): Promise<AutomationRule[]> {
    const params = new URLSearchParams();
    if (isActive !== undefined) params.append('is_active', isActive.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/automation-rules?${params.toString()}`);
    return response.data;
  }

  async createAutomationRule(ruleData: Omit<AutomationRule, 'id' | 'created_at' | 'updated_at'>): Promise<{
    message: string;
    rule_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/automation-rules`, ruleData);
    return response.data;
  }

  async updateAutomationRule(ruleId: string, updateData: Partial<AutomationRule>): Promise<{
    message: string;
    rule_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/automation-rules/${ruleId}`, updateData);
    return response.data;
  }

  // Threat Intelligence
  async getThreatIntelligence(
    indicatorType?: string,
    threatType?: string,
    confidence?: number,
    limit: number = 100
  ): Promise<ThreatIntelligence[]> {
    const params = new URLSearchParams();
    if (indicatorType) params.append('indicator_type', indicatorType);
    if (threatType) params.append('threat_type', threatType);
    if (confidence) params.append('confidence', confidence.toString());
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/threat-intelligence?${params.toString()}`);
    return response.data;
  }

  async addThreatIntelligence(intelData: Omit<ThreatIntelligence, 'id'>): Promise<{
    message: string;
    intel_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/threat-intelligence`, intelData);
    return response.data;
  }

  // Dashboards
  async getDashboards(): Promise<Dashboard[]> {
    const response = await apiClient.get(`${this.baseUrl}/dashboards`);
    return response.data;
  }

  async getDashboardData(dashboardId: string): Promise<{
    dashboard: Dashboard;
    data: Record<string, any>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/dashboards/${dashboardId}/data`);
    return response.data;
  }

  // Metrics and Analytics
  async getMetrics(
    metricNames: string[],
    startTime: string,
    endTime: string,
    interval: string = '1h'
  ): Promise<MetricsData[]> {
    const response = await apiClient.post(`${this.baseUrl}/metrics`, {
      metric_names: metricNames,
      start_time: startTime,
      end_time: endTime,
      interval
    });
    return response.data;
  }

  async getRealTimeMetrics(metricNames: string[]): Promise<Record<string, number>> {
    const response = await apiClient.post(`${this.baseUrl}/metrics/realtime`, {
      metric_names: metricNames
    });
    return response.data;
  }

  // Correlation and Analysis
  async correlateEvents(eventIds: string[]): Promise<{
    correlation_id: string;
    events: SecurityEvent[];
    patterns: string[];
    risk_score: number;
    recommendations: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/correlation`, {
      event_ids: eventIds
    });
    return response.data;
  }

  async getEventPatterns(
    startTime: string,
    endTime: string,
    patternType?: string
  ): Promise<{
    patterns: Array<{
      pattern: string;
      frequency: number;
      severity: string;
      affected_assets: string[];
      first_seen: string;
      last_seen: string;
    }>;
  }> {
    const params = new URLSearchParams();
    params.append('start_time', startTime);
    params.append('end_time', endTime);
    if (patternType) params.append('pattern_type', patternType);
    
    const response = await apiClient.get(`${this.baseUrl}/patterns?${params.toString()}`);
    return response.data;
  }
}

export const monitoringSiemSoarService = new MonitoringSiemSoarService();
