import { apiClient } from '../utils/apiClient';

// Enums matching backend schemas
export enum IncidentSeverity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical"
}

export enum IncidentStatus {
  OPEN = "open",
  IN_PROGRESS = "in_progress",
  RESOLVED = "resolved",
  CLOSED = "closed"
}

export enum IncidentType {
  PHISHING = "phishing",
  MALWARE = "malware",
  DATA_BREACH = "data_breach",
  UNAUTHORIZED_ACCESS = "unauthorized_access",
  CLOUD_MISCONFIGURATION = "cloud_misconfiguration",
  NETWORK_ATTACK = "network_attack",
  OTHER = "other"
}

// Base interfaces matching backend schemas
export interface IncidentBase {
  title: string;
  description?: string;
  incident_type: IncidentType;
  severity: IncidentSeverity;
  source?: string;
  source_id?: string;
  tags?: string[];
  incident_metadata?: Record<string, any>;
  ioc_data?: Record<string, any>;
}

export interface IncidentResponseBase {
  response_type: string;
  description: string;
  action_taken?: string;
  outcome?: string;
  response_metadata?: Record<string, any>;
}

export interface ResponsePlaybookBase {
  name: string;
  description?: string;
  steps?: Record<string, any>[];
  incident_types?: string[];
  is_active?: boolean;
}

// Create interfaces
export interface IncidentCreate extends IncidentBase {}

export interface IncidentUpdate {
  title?: string;
  description?: string;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  assigned_to?: number;
  tags?: string[];
  incident_metadata?: Record<string, any>;
  ioc_data?: Record<string, any>;
}

export interface IncidentResponseCreate extends IncidentResponseBase {
  incident_id: number;
}

export interface IncidentResponseUpdate {
  description?: string;
  action_taken?: string;
  outcome?: string;
  response_metadata?: Record<string, any>;
}

export interface ResponsePlaybookCreate extends ResponsePlaybookBase {}

export interface ResponsePlaybookUpdate {
  name?: string;
  description?: string;
  steps?: Record<string, any>[];
  is_active?: boolean;
}

// Response interfaces
export interface IncidentInDB extends IncidentBase {
  id: number;
  status: IncidentStatus;
  assigned_to?: number;
  created_by: number;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  closed_at?: string;
}

export interface Incident extends IncidentInDB {
  assigned_user?: User;
  creator: User;
  response_count: number;
  playbook_count: number;
}

export interface IncidentResponseInDB extends IncidentResponseBase {
  id: number;
  incident_id: number;
  performed_by: number;
  performed_at: string;
}

export interface IncidentResponse extends IncidentResponseInDB {
  user: User;
}

export interface ResponsePlaybookInDB extends ResponsePlaybookBase {
  id: number;
  incident_id: number;
  created_at: string;
  updated_at: string;
}

export interface ResponsePlaybook extends ResponsePlaybookInDB {}

export interface PlaybookStep {
  step_number: number;
  title: string;
  description: string;
  action_type: string; // manual, automated, notification
  action_details: Record<string, any>;
  estimated_time?: number; // minutes
  dependencies?: number[];
  required_approval: boolean;
}

// Filter and statistics interfaces
export interface IncidentFilter {
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  incident_type?: IncidentType;
  assigned_to?: number;
  created_by?: number;
  date_from?: string;
  date_to?: string;
  tags?: string[];
  search?: string;
}

export interface IncidentStats {
  total_incidents: number;
  open_incidents: number;
  in_progress_incidents: number;
  resolved_incidents: number;
  closed_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
  avg_resolution_time?: number; // hours
  incidents_by_type: Record<string, number>;
  incidents_by_severity: Record<string, number>;
}

export interface IncidentBulkUpdate {
  incident_ids: number[];
  updates: IncidentUpdate;
}

// Response wrapper interfaces
export interface IncidentResponseWrapper {
  incidents: Incident[];
  total: number;
  skip: number;
  limit: number;
}

// User interface (simplified for incidents)
interface User {
  id: number;
  email: string;
  username: string;
  full_name?: string;
  role: string;
}

class IncidentService {
  // Get all incidents with filtering and pagination
  async getIncidents(
    skip: number = 0,
    limit: number = 100,
    status?: IncidentStatus,
    severity?: IncidentSeverity,
    incident_type?: IncidentType,
    assigned_to?: number,
    created_by?: number,
    date_from?: string,
    date_to?: string,
    tags?: string[],
    search?: string
  ): Promise<IncidentResponseWrapper> {
    const params = new URLSearchParams();
    if (skip) params.append('skip', skip.toString());
    if (limit) params.append('limit', limit.toString());
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (incident_type) params.append('incident_type', incident_type);
    if (assigned_to) params.append('assigned_to', assigned_to.toString());
    if (created_by) params.append('created_by', created_by.toString());
    if (date_from) params.append('date_from', date_from);
    if (date_to) params.append('date_to', date_to);
    if (tags) tags.forEach(tag => params.append('tags', tag));
    if (search) params.append('search', search);

    const response = await apiClient.get(`/incidents/?${params.toString()}`);
    return response.data;
  }

  // Get incident by ID
  async getIncident(incidentId: number): Promise<Incident> {
    const response = await apiClient.get(`/incidents/${incidentId}`);
    return response.data;
  }

  // Create new incident
  async createIncident(incidentData: IncidentCreate): Promise<Incident> {
    const response = await apiClient.post('/incidents/', incidentData);
    return response.data;
  }

  // Update incident
  async updateIncident(incidentId: number, updateData: IncidentUpdate): Promise<Incident> {
    const response = await apiClient.put(`/incidents/${incidentId}`, updateData);
    return response.data;
  }

  // Delete incident
  async deleteIncident(incidentId: number): Promise<{ message: string }> {
    const response = await apiClient.delete(`/incidents/${incidentId}`);
    return response.data;
  }

  // Get incident statistics
  async getIncidentStats(): Promise<IncidentStats> {
    const response = await apiClient.get('/incidents/stats');
    return response.data;
  }

  // Get response playbooks
  async getResponsePlaybooks(): Promise<ResponsePlaybook[]> {
    const response = await apiClient.get('/incidents/playbooks');
    return response.data;
  }

  // Create response playbook
  async createResponsePlaybook(playbookData: ResponsePlaybookCreate): Promise<ResponsePlaybook> {
    const response = await apiClient.post('/incidents/playbooks', playbookData);
    return response.data;
  }

  // Add incident response
  async addIncidentResponse(
    incidentId: number,
    responseData: IncidentResponseCreate
  ): Promise<IncidentResponse> {
    const response = await apiClient.post(`/incidents/${incidentId}/responses`, responseData);
    return response.data;
  }

  // Get incident responses
  async getIncidentResponses(incidentId: number): Promise<IncidentResponse[]> {
    const response = await apiClient.get(`/incidents/${incidentId}/responses`);
    return response.data;
  }

  // Update incident response
  async updateIncidentResponse(
    incidentId: number,
    responseId: number,
    updateData: IncidentResponseUpdate
  ): Promise<IncidentResponse> {
    const response = await apiClient.put(`/incidents/${incidentId}/responses/${responseId}`, updateData);
    return response.data;
  }

  // Delete incident response
  async deleteIncidentResponse(
    incidentId: number,
    responseId: number
  ): Promise<{ message: string }> {
    const response = await apiClient.delete(`/incidents/${incidentId}/responses/${responseId}`);
    return response.data;
  }

  // Get incident playbooks
  async getIncidentPlaybooks(incidentId: number): Promise<ResponsePlaybook[]> {
    const response = await apiClient.get(`/incidents/${incidentId}/playbooks`);
    return response.data;
  }

  // Create incident playbook
  async createIncidentPlaybook(
    incidentId: number,
    playbookData: ResponsePlaybookCreate
  ): Promise<ResponsePlaybook> {
    const response = await apiClient.post(`/incidents/${incidentId}/playbooks`, playbookData);
    return response.data;
  }

  // Update incident playbook
  async updateIncidentPlaybook(
    incidentId: number,
    playbookId: number,
    updateData: ResponsePlaybookUpdate
  ): Promise<ResponsePlaybook> {
    const response = await apiClient.put(`/incidents/${incidentId}/playbooks/${playbookId}`, updateData);
    return response.data;
  }

  // Delete incident playbook
  async deleteIncidentPlaybook(
    incidentId: number,
    playbookId: number
  ): Promise<{ message: string }> {
    const response = await apiClient.delete(`/incidents/${incidentId}/playbooks/${playbookId}`);
    return response.data;
  }

  // Bulk update incidents
  async bulkUpdateIncidents(bulkUpdateData: IncidentBulkUpdate): Promise<{ message: string }> {
    const response = await apiClient.put('/incidents/bulk-update', bulkUpdateData);
    return response.data;
  }

  // Assign incident to user
  async assignIncident(incidentId: number, userId: number): Promise<Incident> {
    const response = await apiClient.put(`/incidents/${incidentId}/assign`, { assigned_to: userId });
    return response.data;
  }

  // Change incident status
  async changeIncidentStatus(incidentId: number, status: IncidentStatus): Promise<Incident> {
    const response = await apiClient.put(`/incidents/${incidentId}/status`, { status });
    return response.data;
  }

  // Add tags to incident
  async addIncidentTags(incidentId: number, tags: string[]): Promise<Incident> {
    const response = await apiClient.put(`/incidents/${incidentId}/tags`, { tags });
    return response.data;
  }

  // Remove tags from incident
  async removeIncidentTags(incidentId: number, tags: string[]): Promise<Incident> {
    const response = await apiClient.delete(`/incidents/${incidentId}/tags`, { data: { tags } });
    return response.data;
  }

  // Get incidents by user
  async getIncidentsByUser(userId: number): Promise<Incident[]> {
    const response = await apiClient.get(`/incidents/user/${userId}`);
    return response.data;
  }

  // Get incidents by team
  async getIncidentsByTeam(teamId: number): Promise<Incident[]> {
    const response = await apiClient.get(`/incidents/team/${teamId}`);
    return response.data;
  }

  // Export incidents
  async exportIncidents(format: 'csv' | 'json' | 'pdf' = 'csv'): Promise<Blob> {
    const response = await apiClient.get(`/incidents/export?format=${format}`, {
      responseType: 'blob'
    });
    return response.data;
  }

  // Get incident timeline
  async getIncidentTimeline(incidentId: number): Promise<Record<string, any>[]> {
    const response = await apiClient.get(`/incidents/${incidentId}/timeline`);
    return response.data;
  }

  // Get incident metrics
  async getIncidentMetrics(
    dateFrom?: string,
    dateTo?: string,
    teamId?: number
  ): Promise<Record<string, any>> {
    const params = new URLSearchParams();
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (teamId) params.append('team_id', teamId.toString());

    const response = await apiClient.get(`/incidents/metrics?${params.toString()}`);
    return response.data;
  }
}

export const incidentService = new IncidentService();
export default incidentService;
