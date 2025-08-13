import { apiClient } from '../utils/apiClient';

export interface Project {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'inactive' | 'completed' | 'on_hold';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  start_date: string;
  end_date?: string;
  owner_id: string;
  owner_name: string;
  team_members: ProjectMember[];
  budget?: number;
  actual_cost?: number;
  progress_percentage: number;
  tags: string[];
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ProjectMember {
  user_id: string;
  username: string;
  role: 'owner' | 'manager' | 'member' | 'viewer';
  permissions: string[];
  joined_at: string;
}

export interface ProjectTask {
  id: string;
  project_id: string;
  title: string;
  description: string;
  status: 'todo' | 'in_progress' | 'review' | 'completed' | 'blocked';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  assigned_to?: string;
  assigned_username?: string;
  due_date?: string;
  estimated_hours?: number;
  actual_hours?: number;
  dependencies: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface ProjectMilestone {
  id: string;
  project_id: string;
  title: string;
  description: string;
  target_date: string;
  status: 'upcoming' | 'in_progress' | 'completed' | 'overdue';
  completion_percentage: number;
  deliverables: string[];
  dependencies: string[];
  created_at: string;
  updated_at: string;
}

export interface ProjectRisk {
  id: string;
  project_id: string;
  title: string;
  description: string;
  risk_type: 'technical' | 'schedule' | 'cost' | 'resource' | 'external';
  probability: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high' | 'critical';
  risk_score: number;
  status: 'identified' | 'assessed' | 'mitigated' | 'closed';
  mitigation_strategy?: string;
  contingency_plan?: string;
  assigned_to?: string;
  due_date?: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectDocument {
  id: string;
  project_id: string;
  title: string;
  description: string;
  file_type: string;
  file_size: number;
  file_path: string;
  version: string;
  uploaded_by: string;
  uploaded_at: string;
  tags: string[];
  is_public: boolean;
}

export interface ProjectReport {
  id: string;
  project_id: string;
  report_type: 'progress' | 'status' | 'financial' | 'risk' | 'quality';
  title: string;
  content: string;
  generated_by: string;
  generated_at: string;
  period_start?: string;
  period_end?: string;
  data: Record<string, any>;
}

class ProjectsService {
  private baseUrl = '/api/v1/projects';

  // Project Management
  async getProjects(
    status?: string,
    priority?: string,
    ownerId?: string,
    limit: number = 100
  ): Promise<Project[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (priority) params.append('priority', priority);
    if (ownerId) params.append('owner_id', ownerId);
    if (limit) params.append('limit', limit.toString());

    const response = await apiClient.get(`${this.baseUrl}?${params}`);
    return response.data;
  }

  async getProject(projectId: string): Promise<Project> {
    const response = await apiClient.get(`${this.baseUrl}/${projectId}`);
    return response.data;
  }

  async createProject(projectData: Omit<Project, 'id' | 'created_at' | 'updated_at'>): Promise<{
    message: string;
    project_id: string;
  }> {
    const response = await apiClient.post(this.baseUrl, projectData);
    return response.data;
  }

  async updateProject(projectId: string, updateData: Partial<Project>): Promise<{
    message: string;
    project_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${projectId}`, updateData);
    return response.data;
  }

  async deleteProject(projectId: string): Promise<{
    message: string;
    project_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${projectId}`);
    return response.data;
  }

  // Project Members Management
  async getProjectMembers(projectId: string): Promise<ProjectMember[]> {
    const response = await apiClient.get(`${this.baseUrl}/${projectId}/members`);
    return response.data;
  }

  async addProjectMember(
    projectId: string,
    userId: string,
    role: string,
    permissions: string[]
  ): Promise<{
    message: string;
    member_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/members`, {
      user_id: userId,
      role,
      permissions
    });
    return response.data;
  }

  async updateProjectMember(
    projectId: string,
    userId: string,
    role: string,
    permissions: string[]
  ): Promise<{
    message: string;
    member_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${projectId}/members/${userId}`, {
      role,
      permissions
    });
    return response.data;
  }

  async removeProjectMember(projectId: string, userId: string): Promise<{
    message: string;
    member_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${projectId}/members/${userId}`);
    return response.data;
  }

  // Task Management
  async getProjectTasks(
    projectId: string,
    status?: string,
    priority?: string,
    assignedTo?: string
  ): Promise<ProjectTask[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (priority) params.append('priority', priority);
    if (assignedTo) params.append('assigned_to', assignedTo);

    const response = await apiClient.get(`${this.baseUrl}/${projectId}/tasks?${params}`);
    return response.data;
  }

  async getProjectTask(projectId: string, taskId: string): Promise<ProjectTask> {
    const response = await apiClient.get(`${this.baseUrl}/${projectId}/tasks/${taskId}`);
    return response.data;
  }

  async createProjectTask(
    projectId: string,
    taskData: Omit<ProjectTask, 'id' | 'project_id' | 'created_at' | 'updated_at'>
  ): Promise<{
    message: string;
    task_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/tasks`, taskData);
    return response.data;
  }

  async updateProjectTask(
    projectId: string,
    taskId: string,
    updateData: Partial<ProjectTask>
  ): Promise<{
    message: string;
    task_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${projectId}/tasks/${taskId}`, updateData);
    return response.data;
  }

  async deleteProjectTask(projectId: string, taskId: string): Promise<{
    message: string;
    task_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${projectId}/tasks/${taskId}`);
    return response.data;
  }

  // Milestone Management
  async getProjectMilestones(projectId: string, status?: string): Promise<ProjectMilestone[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);

    const response = await apiClient.get(`${this.baseUrl}/${projectId}/milestones?${params}`);
    return response.data;
  }

  async createProjectMilestone(
    projectId: string,
    milestoneData: Omit<ProjectMilestone, 'id' | 'project_id' | 'created_at' | 'updated_at'>
  ): Promise<{
    message: string;
    milestone_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/milestones`, milestoneData);
    return response.data;
  }

  async updateProjectMilestone(
    projectId: string,
    milestoneId: string,
    updateData: Partial<ProjectMilestone>
  ): Promise<{
    message: string;
    milestone_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${projectId}/milestones/${milestoneId}`, updateData);
    return response.data;
  }

  async deleteProjectMilestone(projectId: string, milestoneId: string): Promise<{
    message: string;
    milestone_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${projectId}/milestones/${milestoneId}`);
    return response.data;
  }

  // Risk Management
  async getProjectRisks(projectId: string, status?: string, riskType?: string): Promise<ProjectRisk[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (riskType) params.append('risk_type', riskType);

    const response = await apiClient.get(`${this.baseUrl}/${projectId}/risks?${params}`);
    return response.data;
  }

  async createProjectRisk(
    projectId: string,
    riskData: Omit<ProjectRisk, 'id' | 'project_id' | 'created_at' | 'updated_at'>
  ): Promise<{
    message: string;
    risk_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/risks`, riskData);
    return response.data;
  }

  async updateProjectRisk(
    projectId: string,
    riskId: string,
    updateData: Partial<ProjectRisk>
  ): Promise<{
    message: string;
    risk_id: string;
  }> {
    const response = await apiClient.put(`${this.baseUrl}/${projectId}/risks/${riskId}`, updateData);
    return response.data;
  }

  async deleteProjectRisk(projectId: string, riskId: string): Promise<{
    message: string;
    risk_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${projectId}/risks/${riskId}`);
    return response.data;
  }

  // Document Management
  async getProjectDocuments(projectId: string, fileType?: string): Promise<ProjectDocument[]> {
    const params = new URLSearchParams();
    if (fileType) params.append('file_type', fileType);

    const response = await apiClient.get(`${this.baseUrl}/${projectId}/documents?${params}`);
    return response.data;
  }

  async uploadProjectDocument(
    projectId: string,
    file: File,
    title: string,
    description: string,
    tags: string[],
    isPublic: boolean = false
  ): Promise<{
    message: string;
    document_id: string;
  }> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title);
    formData.append('description', description);
    formData.append('tags', JSON.stringify(tags));
    formData.append('is_public', isPublic.toString());

    const response = await apiClient.post(`${this.baseUrl}/${projectId}/documents`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  async deleteProjectDocument(projectId: string, documentId: string): Promise<{
    message: string;
    document_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${projectId}/documents/${documentId}`);
    return response.data;
  }

  // Reporting
  async getProjectReports(projectId: string, reportType?: string): Promise<ProjectReport[]> {
    const params = new URLSearchParams();
    if (reportType) params.append('report_type', reportType);

    const response = await apiClient.get(`${this.baseUrl}/${projectId}/reports?${params}`);
    return response.data;
  }

  async generateProjectReport(
    projectId: string,
    reportType: string,
    periodStart?: string,
    periodEnd?: string
  ): Promise<{
    message: string;
    report_id: string;
    report_url: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/reports/generate`, {
      report_type: reportType,
      period_start: periodStart,
      period_end: periodEnd
    });
    return response.data;
  }

  // Analytics and Dashboard
  async getProjectSummary(projectId: string): Promise<{
    project_id: string;
    total_tasks: number;
    completed_tasks: number;
    in_progress_tasks: number;
    overdue_tasks: number;
    progress_percentage: number;
    total_milestones: number;
    completed_milestones: number;
    total_risks: number;
    high_risk_count: number;
    budget_utilization: number;
    team_size: number;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${projectId}/summary`);
    return response.data;
  }

  async getProjectTimeline(projectId: string): Promise<{
    project_id: string;
    milestones: ProjectMilestone[];
    tasks: ProjectTask[];
    risks: ProjectRisk[];
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${projectId}/timeline`);
    return response.data;
  }

  async getProjectGanttData(projectId: string): Promise<{
    project_id: string;
    tasks: Array<{
      id: string;
      title: string;
      start_date: string;
      end_date: string;
      progress: number;
      dependencies: string[];
    }>;
    milestones: Array<{
      id: string;
      title: string;
      date: string;
    }>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${projectId}/gantt`);
    return response.data;
  }

  // Bulk Operations
  async bulkUpdateTaskStatus(
    projectId: string,
    taskIds: string[],
    status: string
  ): Promise<{
    message: string;
    updated_count: number;
    failed_count: number;
    failed_tasks: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/tasks/bulk-update`, {
      task_ids: taskIds,
      status
    });
    return response.data;
  }

  async bulkAssignTasks(
    projectId: string,
    taskIds: string[],
    assignedTo: string
  ): Promise<{
    message: string;
    updated_count: number;
    failed_count: number;
    failed_tasks: string[];
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${projectId}/tasks/bulk-assign`, {
      task_ids: taskIds,
      assigned_to: assignedTo
    });
    return response.data;
  }
}

export const projectsService = new ProjectsService();
export default projectsService;
