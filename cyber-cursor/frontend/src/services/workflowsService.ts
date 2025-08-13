import { apiClient } from '../utils/apiClient';

export interface Workflow {
  id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  trigger_type: 'manual' | 'automatic' | 'scheduled' | 'event_based';
  trigger_conditions: TriggerCondition[];
  steps: WorkflowStep[];
  variables: WorkflowVariable[];
  is_active: boolean;
  is_template: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  last_executed?: string;
  execution_count: number;
  success_rate: number;
  estimated_duration: string;
  tags: string[];
}

export interface WorkflowStep {
  id: string;
  order: number;
  name: string;
  description: string;
  step_type: 'action' | 'condition' | 'loop' | 'wait' | 'integration' | 'notification';
  action_type?: string;
  parameters: Record<string, any>;
  timeout_seconds: number;
  retry_count: number;
  retry_delay: number;
  is_required: boolean;
  error_handling: 'continue' | 'stop' | 'retry' | 'fallback';
  fallback_action?: string;
  dependencies: string[];
  outputs: string[];
  validation_rules?: string[];
}

export interface WorkflowVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  default_value?: any;
  is_required: boolean;
  description: string;
  validation_rules?: string[];
  scope: 'global' | 'workflow' | 'step';
}

export interface TriggerCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'exists' | 'not_exists';
  value: any;
  logical_operator?: 'AND' | 'OR';
}

export interface WorkflowExecution {
  id: string;
  workflow_id: string;
  workflow_name: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled' | 'paused';
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  current_step?: string;
  progress: number;
  variables: Record<string, any>;
  outputs: Record<string, any>;
  error_message?: string;
  error_details?: any;
  executed_by: string;
  execution_context: Record<string, any>;
  logs: ExecutionLog[];
}

export interface ExecutionLog {
  id: string;
  timestamp: string;
  step_id: string;
  step_name: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  message: string;
  details?: any;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  use_cases: string[];
  complexity: 'simple' | 'medium' | 'complex';
  estimated_setup_time: string;
  prerequisites: string[];
  steps_count: number;
  variables_count: number;
  is_official: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  rating: number;
  usage_count: number;
}

export interface WorkflowValidation {
  is_valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: string[];
}

export interface ValidationError {
  step_id?: string;
  field: string;
  message: string;
  severity: 'error' | 'critical';
  suggestion?: string;
}

export interface ValidationWarning {
  step_id?: string;
  field: string;
  message: string;
  suggestion?: string;
}

export interface WorkflowMetrics {
  total_workflows: number;
  active_workflows: number;
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  average_execution_time: number;
  success_rate: number;
  most_used_workflows: Array<{
    workflow_id: string;
    workflow_name: string;
    execution_count: number;
    success_rate: number;
  }>;
  execution_trends: Array<{
    date: string;
    executions: number;
    success_rate: number;
    average_time: number;
  }>;
}

export interface WorkflowSchedule {
  id: string;
  workflow_id: string;
  name: string;
  description: string;
  schedule_type: 'cron' | 'interval' | 'calendar';
  schedule_expression: string;
  timezone: string;
  is_active: boolean;
  next_execution: string;
  last_execution?: string;
  execution_count: number;
  created_at: string;
  updated_at: string;
}

class WorkflowsService {
  private baseUrl = '/api/v1/workflows';

  // Workflow Management
  async getWorkflows(
    category?: string,
    isActive?: boolean,
    isTemplate?: boolean
  ): Promise<Workflow[]> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (isActive !== undefined) params.append('is_active', isActive.toString());
    if (isTemplate !== undefined) params.append('is_template', isTemplate.toString());
    
    const response = await apiClient.get(`${this.baseUrl}?${params.toString()}`);
    return response.data;
  }

  async getWorkflow(workflowId: string): Promise<Workflow> {
    const response = await apiClient.get(`${this.baseUrl}/${workflowId}`);
    return response.data;
  }

  async createWorkflow(workflowData: Omit<Workflow, 'id' | 'created_at' | 'updated_at' | 'execution_count' | 'success_rate' | 'last_executed'>): Promise<{
    message: string;
    workflow_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}`, workflowData);
    return response.data;
  }

  async updateWorkflow(
    workflowId: string,
    updateData: Partial<Workflow>
  ): Promise<{
    message: string;
    workflow_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/${workflowId}`, updateData);
    return response.data;
  }

  async deleteWorkflow(workflowId: string): Promise<{
    message: string;
    workflow_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/${workflowId}`);
    return response.data;
  }

  async duplicateWorkflow(
    workflowId: string,
    newName: string,
    newDescription?: string
  ): Promise<{
    message: string;
    new_workflow_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${workflowId}/duplicate`, {
      new_name: newName,
      new_description: newDescription
    });
    return response.data;
  }

  // Workflow Execution
  async executeWorkflow(
    workflowId: string,
    variables?: Record<string, any>,
    context?: Record<string, any>
  ): Promise<{
    message: string;
    execution_id: string;
    status: string;
    estimated_duration: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${workflowId}/execute`, {
      variables,
      context
    });
    return response.data;
  }

  async getWorkflowExecution(executionId: string): Promise<WorkflowExecution> {
    const response = await apiClient.get(`${this.baseUrl}/executions/${executionId}`);
    return response.data;
  }

  async getWorkflowExecutions(
    workflowId?: string,
    status?: string,
    startDate?: string,
    endDate?: string,
    limit: number = 100
  ): Promise<WorkflowExecution[]> {
    const params = new URLSearchParams();
    if (workflowId) params.append('workflow_id', workflowId);
    if (status) params.append('status', status);
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('limit', limit.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/executions?${params.toString()}`);
    return response.data;
  }

  async cancelWorkflowExecution(executionId: string): Promise<{
    message: string;
    execution_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/executions/${executionId}/cancel`);
    return response.data;
  }

  async pauseWorkflowExecution(executionId: string): Promise<{
    message: string;
    execution_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/executions/${executionId}/pause`);
    return response.data;
  }

  async resumeWorkflowExecution(executionId: string): Promise<{
    message: string;
    execution_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/executions/${executionId}/resume`);
    return response.data;
  }

  // Workflow Templates
  async getWorkflowTemplates(
    category?: string,
    complexity?: string,
    isOfficial?: boolean
  ): Promise<WorkflowTemplate[]> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (complexity) params.append('complexity', complexity);
    if (isOfficial !== undefined) params.append('is_official', isOfficial.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/templates?${params.toString()}`);
    return response.data;
  }

  async createWorkflowFromTemplate(
    templateId: string,
    workflowName: string,
    workflowDescription?: string,
    variables?: Record<string, any>
  ): Promise<{
    message: string;
    workflow_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/templates/${templateId}/create`, {
      workflow_name: workflowName,
      workflow_description: workflowDescription,
      variables
    });
    return response.data;
  }

  // Workflow Validation
  async validateWorkflow(workflowData: Partial<Workflow>): Promise<WorkflowValidation> {
    const response = await apiClient.post(`${this.baseUrl}/validate`, workflowData);
    return response.data;
  }

  async testWorkflow(
    workflowId: string,
    testVariables?: Record<string, any>
  ): Promise<{
    message: string;
    test_execution_id: string;
    status: string;
    results: any;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${workflowId}/test`, {
      test_variables: testVariables
    });
    return response.data;
  }

  // Workflow Scheduling
  async getWorkflowSchedules(workflowId?: string, isActive?: boolean): Promise<WorkflowSchedule[]> {
    const params = new URLSearchParams();
    if (workflowId) params.append('workflow_id', workflowId);
    if (isActive !== undefined) params.append('is_active', isActive.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/schedules?${params.toString()}`);
    return response.data;
  }

  async createWorkflowSchedule(
    scheduleData: Omit<WorkflowSchedule, 'id' | 'created_at' | 'updated_at' | 'next_execution' | 'last_execution' | 'execution_count'>
  ): Promise<{
    message: string;
    schedule_id: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/schedules`, scheduleData);
    return response.data;
  }

  async updateWorkflowSchedule(
    scheduleId: string,
    updateData: Partial<WorkflowSchedule>
  ): Promise<{
    message: string;
    schedule_id: string;
    status: string;
  }> {
    const response = await apiClient.patch(`${this.baseUrl}/schedules/${scheduleId}`, updateData);
    return response.data;
  }

  async deleteWorkflowSchedule(scheduleId: string): Promise<{
    message: string;
    schedule_id: string;
  }> {
    const response = await apiClient.delete(`${this.baseUrl}/schedules/${scheduleId}`);
    return response.data;
  }

  // Workflow Metrics
  async getWorkflowMetrics(
    startDate?: string,
    endDate?: string,
    includeTrends: boolean = true
  ): Promise<WorkflowMetrics> {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    params.append('include_trends', includeTrends.toString());
    
    const response = await apiClient.get(`${this.baseUrl}/metrics?${params.toString()}`);
    return response.data;
  }

  // Workflow Import/Export
  async exportWorkflow(workflowId: string, format: 'json' | 'yaml' = 'json'): Promise<{
    message: string;
    workflow_data: any;
    format: string;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${workflowId}/export?format=${format}`);
    return response.data;
  }

  async importWorkflow(
    workflowData: any,
    format: 'json' | 'yaml' = 'json',
    overwrite?: boolean
  ): Promise<{
    message: string;
    workflow_id: string;
    status: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/import`, {
      workflow_data: workflowData,
      format,
      overwrite
    });
    return response.data;
  }

  // Workflow Categories
  async getWorkflowCategories(): Promise<Array<{
    name: string;
    description: string;
    workflow_count: number;
    icon?: string;
  }>> {
    const response = await apiClient.get(`${this.baseUrl}/categories`);
    return response.data;
  }

  // Workflow Search
  async searchWorkflows(
    query: string,
    filters?: Record<string, any>,
    limit: number = 50
  ): Promise<{
    workflows: Workflow[];
    total_count: number;
    facets: Record<string, any>;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/search`, {
      query,
      filters,
      limit
    });
    return response.data;
  }

  // Workflow Dependencies
  async getWorkflowDependencies(workflowId: string): Promise<{
    dependencies: Array<{
      workflow_id: string;
      workflow_name: string;
      dependency_type: string;
      description: string;
    }>;
    dependents: Array<{
      workflow_id: string;
      workflow_name: string;
      dependency_type: string;
      description: string;
    }>;
  }> {
    const response = await apiClient.get(`${this.baseUrl}/${workflowId}/dependencies`);
    return response.data;
  }

  // Workflow Versioning
  async getWorkflowVersions(workflowId: string): Promise<Array<{
    version: string;
    created_at: string;
    created_by: string;
    changes: string[];
    is_current: boolean;
  }>> {
    const response = await apiClient.get(`${this.baseUrl}/${workflowId}/versions`);
    return response.data;
  }

  async revertToVersion(workflowId: string, version: string): Promise<{
    message: string;
    workflow_id: string;
    reverted_version: string;
  }> {
    const response = await apiClient.post(`${this.baseUrl}/${workflowId}/revert`, {
      version
    });
    return response.data;
  }
}

export const workflowsService = new WorkflowsService();
