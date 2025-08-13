import { apiClient } from '../utils/apiClient';

// Enums for quality goals
export enum QualityGoalStatus {
  ACTIVE = "ACTIVE",
  INACTIVE = "INACTIVE",
  ARCHIVED = "ARCHIVED"
}

export enum QualityGoalType {
  SECURITY = "SECURITY",
  PERFORMANCE = "PERFORMANCE",
  RELIABILITY = "RELIABILITY",
  MAINTAINABILITY = "MAINTAINABILITY",
  ACCESSIBILITY = "ACCESSIBILITY"
}

export enum QualityGoalPriority {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}

// Interfaces
export interface QualityGoalBase {
  name: string;
  description: string;
  type: QualityGoalType;
  priority: QualityGoalPriority;
  target_value: number;
  current_value: number;
  unit: string;
  deadline?: string;
  status: QualityGoalStatus;
}

export interface QualityGoalCreate extends QualityGoalBase {
  project_id?: string;
  team_id?: string;
  tags?: string[];
}

export interface QualityGoalUpdate extends Partial<QualityGoalBase> {
  id: string;
}

export interface QualityGoalResponse extends QualityGoalBase {
  id: string;
  project_id?: string;
  team_id?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
  created_by: string;
  progress_percentage: number;
  is_on_track: boolean;
  last_updated: string;
}

export interface QualityGoalsResponse {
  goals: QualityGoalResponse[];
  total: number;
  page: number;
  limit: number;
}

export interface QualityGoalMetrics {
  total_goals: number;
  active_goals: number;
  completed_goals: number;
  overdue_goals: number;
  goals_by_type: Record<string, number>;
  goals_by_priority: Record<string, number>;
  goals_by_status: Record<string, number>;
  average_progress: number;
  on_track_percentage: number;
}

export interface QualityGoalFilter {
  type?: QualityGoalType;
  priority?: QualityGoalPriority;
  status?: QualityGoalStatus;
  project_id?: string;
  team_id?: string;
  deadline_from?: string;
  deadline_to?: string;
  tags?: string[];
}

class QualityGoalsService {
  private baseUrl = '/api/v1/quality-goals';

  // Get all quality goals with pagination and filtering
  async getQualityGoals(
    page: number = 1,
    limit: number = 20,
    filter?: QualityGoalFilter
  ): Promise<QualityGoalsResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...(filter?.type && { type: filter.type }),
      ...(filter?.priority && { priority: filter.priority }),
      ...(filter?.status && { status: filter.status }),
      ...(filter?.project_id && { project_id: filter.project_id }),
      ...(filter?.team_id && { team_id: filter.team_id }),
      ...(filter?.deadline_from && { deadline_from: filter.deadline_from }),
      ...(filter?.deadline_to && { deadline_to: filter.deadline_to }),
      ...(filter?.tags && { tags: filter.tags.join(',') })
    });

    const response = await apiClient.get(`${this.baseUrl}?${params}`);
    return response.data;
  }

  // Get a specific quality goal by ID
  async getQualityGoal(goalId: string): Promise<QualityGoalResponse> {
    const response = await apiClient.get(`${this.baseUrl}/${goalId}`);
    return response.data;
  }

  // Create a new quality goal
  async createQualityGoal(goalData: QualityGoalCreate): Promise<QualityGoalResponse> {
    const response = await apiClient.post(this.baseUrl, goalData);
    return response.data;
  }

  // Update an existing quality goal
  async updateQualityGoal(goalId: string, goalData: QualityGoalUpdate): Promise<QualityGoalResponse> {
    const response = await apiClient.put(`${this.baseUrl}/${goalId}`, goalData);
    return response.data;
  }

  // Delete a quality goal
  async deleteQualityGoal(goalId: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${goalId}`);
  }

  // Get quality goals for a specific project
  async getProjectQualityGoals(
    projectId: string,
    page: number = 1,
    limit: number = 20
  ): Promise<QualityGoalsResponse> {
    const params = new URLSearchParams({
      project_id: projectId,
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/project/${projectId}?${params}`);
    return response.data;
  }

  // Get quality goals for a specific team
  async getTeamQualityGoals(
    teamId: string,
    page: number = 1,
    limit: number = 20
  ): Promise<QualityGoalsResponse> {
    const params = new URLSearchParams({
      team_id: teamId,
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/team/${teamId}?${params}`);
    return response.data;
  }

  // Update goal progress
  async updateGoalProgress(
    goalId: string,
    currentValue: number,
    notes?: string
  ): Promise<QualityGoalResponse> {
    const response = await apiClient.patch(`${this.baseUrl}/${goalId}/progress`, {
      current_value: currentValue,
      notes
    });
    return response.data;
  }

  // Get quality goal metrics and statistics
  async getQualityGoalMetrics(
    projectId?: string,
    teamId?: string,
    dateFrom?: string,
    dateTo?: string
  ): Promise<QualityGoalMetrics> {
    const params = new URLSearchParams();
    if (projectId) params.append('project_id', projectId);
    if (teamId) params.append('team_id', teamId);
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`${this.baseUrl}/metrics?${params}`);
    return response.data;
  }

  // Get overdue quality goals
  async getOverdueQualityGoals(
    page: number = 1,
    limit: number = 20
  ): Promise<QualityGoalsResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/overdue?${params}`);
    return response.data;
  }

  // Get quality goals due soon (within specified days)
  async getGoalsDueSoon(
    days: number = 7,
    page: number = 1,
    limit: number = 20
  ): Promise<QualityGoalsResponse> {
    const params = new URLSearchParams({
      days: days.toString(),
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/due-soon?${params}`);
    return response.data;
  }

  // Bulk update quality goals
  async bulkUpdateQualityGoals(
    goalIds: string[],
    updates: Partial<QualityGoalBase>
  ): Promise<QualityGoalResponse[]> {
    const response = await apiClient.patch(`${this.baseUrl}/bulk-update`, {
      goal_ids: goalIds,
      updates
    });
    return response.data;
  }

  // Archive quality goals
  async archiveQualityGoals(goalIds: string[]): Promise<void> {
    await apiClient.patch(`${this.baseUrl}/archive`, {
      goal_ids: goalIds
    });
  }

  // Get quality goal templates
  async getQualityGoalTemplates(): Promise<QualityGoalBase[]> {
    const response = await apiClient.get(`${this.baseUrl}/templates`);
    return response.data;
  }

  // Create quality goal from template
  async createFromTemplate(
    templateId: string,
    customizations: Partial<QualityGoalBase>
  ): Promise<QualityGoalResponse> {
    const response = await apiClient.post(`${this.baseUrl}/from-template/${templateId}`, customizations);
    return response.data;
  }

  // Get quality goal history
  async getQualityGoalHistory(goalId: string): Promise<any[]> {
    const response = await apiClient.get(`${this.baseUrl}/${goalId}/history`);
    return response.data;
  }

  // Export quality goals report
  async exportQualityGoalsReport(
    format: 'csv' | 'pdf' | 'excel' = 'csv',
    filter?: QualityGoalFilter
  ): Promise<Blob> {
    const params = new URLSearchParams({
      format,
      ...(filter?.type && { type: filter.type }),
      ...(filter?.priority && { priority: filter.priority }),
      ...(filter?.status && { status: filter.status }),
      ...(filter?.project_id && { project_id: filter.project_id }),
      ...(filter?.team_id && { team_id: filter.team_id })
    });

    const response = await apiClient.get(`${this.baseUrl}/export?${params}`, {
      responseType: 'blob'
    });
    return response.data;
  }
}

export const qualityGoalsService = new QualityGoalsService();
export default qualityGoalsService;
