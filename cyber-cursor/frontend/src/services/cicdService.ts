import { apiClient } from '../utils/apiClient';

// Enums for CI/CD
export enum PipelineStatus {
  PENDING = "PENDING",
  RUNNING = "RUNNING",
  SUCCESS = "SUCCESS",
  FAILED = "FAILED",
  CANCELLED = "CANCELLED",
  SKIPPED = "SKIPPED"
}

export enum PipelineTrigger {
  MANUAL = "MANUAL",
  SCHEDULED = "SCHEDULED",
  WEBHOOK = "WEBHOOK",
  PUSH = "PUSH",
  PULL_REQUEST = "PULL_REQUEST",
  MERGE = "MERGE"
}

export enum SecurityScanType {
  SAST = "SAST",
  DAST = "DAST",
  SCA = "SCA",
  CONTAINER_SCAN = "CONTAINER_SCAN",
  INFRASTRUCTURE_SCAN = "INFRASTRUCTURE_SCAN"
}

// Interfaces
export interface PipelineBase {
  name: string;
  description?: string;
  repository_url: string;
  branch: string;
  trigger: PipelineTrigger;
  security_scan_types: SecurityScanType[];
  enabled: boolean;
  schedule?: string;
  webhook_url?: string;
}

export interface PipelineCreate extends PipelineBase {
  project_id?: string;
  team_id?: string;
  environment_variables?: Record<string, string>;
  secrets?: Record<string, string>;
}

export interface PipelineUpdate extends Partial<PipelineBase> {
  id: string;
}

export interface PipelineResponse extends PipelineBase {
  id: string;
  project_id?: string;
  team_id?: string;
  environment_variables?: Record<string, string>;
  secrets?: Record<string, string>;
  created_at: string;
  updated_at: string;
  created_by: string;
  last_run_at?: string;
  last_run_status?: PipelineStatus;
  total_runs: number;
  success_rate: number;
  average_duration: number;
}

export interface PipelineRun {
  id: string;
  pipeline_id: string;
  status: PipelineStatus;
  trigger: PipelineTrigger;
  started_at: string;
  completed_at?: string;
  duration?: number;
  commit_hash?: string;
  commit_message?: string;
  branch: string;
  logs?: string;
  artifacts?: string[];
  security_scan_results?: SecurityScanResult[];
  environment_variables?: Record<string, string>;
}

export interface SecurityScanResult {
  scan_type: SecurityScanType;
  status: PipelineStatus;
  vulnerabilities_found: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  scan_duration: number;
  report_url?: string;
  details?: any;
}

export interface PipelinesResponse {
  pipelines: PipelineResponse[];
  total: number;
  page: number;
  limit: number;
}

export interface PipelineRunsResponse {
  runs: PipelineRun[];
  total: number;
  page: number;
  limit: number;
}

export interface PipelineMetrics {
  total_pipelines: number;
  active_pipelines: number;
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  average_duration: number;
  success_rate: number;
  pipelines_by_status: Record<string, number>;
  runs_by_status: Record<string, number>;
  security_scan_summary: Record<string, number>;
}

export interface PipelineFilter {
  status?: PipelineStatus;
  trigger?: PipelineTrigger;
  security_scan_type?: SecurityScanType;
  project_id?: string;
  team_id?: string;
  enabled?: boolean;
  created_after?: string;
  created_before?: string;
}

class CICDService {
  private baseUrl = '/api/v1/cicd';

  // Get all pipelines with pagination and filtering
  async getPipelines(
    page: number = 1,
    limit: number = 20,
    filter?: PipelineFilter
  ): Promise<PipelinesResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...(filter?.status && { status: filter.status }),
      ...(filter?.trigger && { trigger: filter.trigger }),
      ...(filter?.security_scan_type && { security_scan_type: filter.security_scan_type }),
      ...(filter?.project_id && { project_id: filter.project_id }),
      ...(filter?.team_id && { team_id: filter.team_id }),
      ...(filter?.enabled !== undefined && { enabled: filter.enabled.toString() }),
      ...(filter?.created_after && { created_after: filter.created_after }),
      ...(filter?.created_before && { created_before: filter.created_before })
    });

    const response = await apiClient.get(`${this.baseUrl}/pipelines?${params}`);
    return response.data;
  }

  // Get a specific pipeline by ID
  async getPipeline(pipelineId: string): Promise<PipelineResponse> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}`);
    return response.data;
  }

  // Create a new pipeline
  async createPipeline(pipelineData: PipelineCreate): Promise<PipelineResponse> {
    const response = await apiClient.post(`${this.baseUrl}/pipelines`, pipelineData);
    return response.data;
  }

  // Update an existing pipeline
  async updatePipeline(pipelineId: string, pipelineData: PipelineUpdate): Promise<PipelineResponse> {
    const response = await apiClient.put(`${this.baseUrl}/pipelines/${pipelineId}`, pipelineData);
    return response.data;
  }

  // Delete a pipeline
  async deletePipeline(pipelineId: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/pipelines/${pipelineId}`);
  }

  // Enable/disable a pipeline
  async togglePipeline(pipelineId: string, enabled: boolean): Promise<PipelineResponse> {
    const response = await apiClient.patch(`${this.baseUrl}/pipelines/${pipelineId}/toggle`, {
      enabled
    });
    return response.data;
  }

  // Trigger a pipeline run manually
  async triggerPipeline(pipelineId: string, branch?: string): Promise<PipelineRun> {
    const response = await apiClient.post(`${this.baseUrl}/pipelines/${pipelineId}/trigger`, {
      branch
    });
    return response.data;
  }

  // Get pipeline runs
  async getPipelineRuns(
    pipelineId: string,
    page: number = 1,
    limit: number = 20
  ): Promise<PipelineRunsResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/runs?${params}`);
    return response.data;
  }

  // Get a specific pipeline run
  async getPipelineRun(pipelineId: string, runId: string): Promise<PipelineRun> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}`);
    return response.data;
  }

  // Cancel a pipeline run
  async cancelPipelineRun(pipelineId: string, runId: string): Promise<void> {
    await apiClient.post(`${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/cancel`);
  }

  // Retry a failed pipeline run
  async retryPipelineRun(pipelineId: string, runId: string): Promise<PipelineRun> {
    const response = await apiClient.post(`${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/retry`);
    return response.data;
  }

  // Get pipeline logs
  async getPipelineLogs(pipelineId: string, runId: string): Promise<string> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/logs`);
    return response.data.logs;
  }

  // Get pipeline artifacts
  async getPipelineArtifacts(pipelineId: string, runId: string): Promise<string[]> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/artifacts`);
    return response.data.artifacts;
  }

  // Download pipeline artifact
  async downloadArtifact(pipelineId: string, runId: string, artifactPath: string): Promise<Blob> {
    const response = await apiClient.get(
      `${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/artifacts/download`,
      {
        params: { path: artifactPath },
        responseType: 'blob'
      }
    );
    return response.data;
  }

  // Get security scan results for a pipeline run
  async getSecurityScanResults(pipelineId: string, runId: string): Promise<SecurityScanResult[]> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/security-scan`);
    return response.data.results;
  }

  // Get security scan report
  async getSecurityScanReport(pipelineId: string, runId: string, scanType: SecurityScanType): Promise<Blob> {
    const response = await apiClient.get(
      `${this.baseUrl}/pipelines/${pipelineId}/runs/${runId}/security-scan/${scanType}/report`,
      {
        responseType: 'blob'
      }
    );
    return response.data;
  }

  // Get pipelines for a specific project
  async getProjectPipelines(
    projectId: string,
    page: number = 1,
    limit: number = 20
  ): Promise<PipelinesResponse> {
    const params = new URLSearchParams({
      project_id: projectId,
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/pipelines/project/${projectId}?${params}`);
    return response.data;
  }

  // Get pipelines for a specific team
  async getTeamPipelines(
    teamId: string,
    page: number = 1,
    limit: number = 20
  ): Promise<PipelinesResponse> {
    const params = new URLSearchParams({
      team_id: teamId,
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/pipelines/team/${teamId}?${params}`);
    return response.data;
  }

  // Get CI/CD metrics and statistics
  async getCICDMetrics(
    projectId?: string,
    teamId?: string,
    dateFrom?: string,
    dateTo?: string
  ): Promise<PipelineMetrics> {
    const params = new URLSearchParams();
    if (projectId) params.append('project_id', projectId);
    if (teamId) params.append('team_id', teamId);
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);

    const response = await apiClient.get(`${this.baseUrl}/metrics?${params}`);
    return response.data;
  }

  // Get failed pipelines
  async getFailedPipelines(
    page: number = 1,
    limit: number = 20
  ): Promise<PipelinesResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString()
    });

    const response = await apiClient.get(`${this.baseUrl}/pipelines/failed?${params}`);
    return response.data;
  }

  // Get pipeline templates
  async getPipelineTemplates(): Promise<PipelineBase[]> {
    const response = await apiClient.get(`${this.baseUrl}/templates`);
    return response.data;
  }

  // Create pipeline from template
  async createFromTemplate(
    templateId: string,
    customizations: Partial<PipelineCreate>
  ): Promise<PipelineResponse> {
    const response = await apiClient.post(`${this.baseUrl}/from-template/${templateId}`, customizations);
    return response.data;
  }

  // Validate pipeline configuration
  async validatePipeline(pipelineData: PipelineCreate): Promise<{ valid: boolean; errors: string[] }> {
    const response = await apiClient.post(`${this.baseUrl}/validate`, pipelineData);
    return response.data;
  }

  // Test pipeline connection
  async testPipelineConnection(pipelineData: PipelineCreate): Promise<{ connected: boolean; message: string }> {
    const response = await apiClient.post(`${this.baseUrl}/test-connection`, pipelineData);
    return response.data;
  }

  // Get webhook configuration
  async getWebhookConfig(pipelineId: string): Promise<{ webhook_url: string; secret: string }> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/webhook`);
    return response.data;
  }

  // Regenerate webhook secret
  async regenerateWebhookSecret(pipelineId: string): Promise<{ webhook_url: string; secret: string }> {
    const response = await apiClient.post(`${this.baseUrl}/pipelines/${pipelineId}/webhook/regenerate`);
    return response.data;
  }

  // Export pipeline configuration
  async exportPipelineConfig(pipelineId: string, format: 'yaml' | 'json' = 'yaml'): Promise<string> {
    const response = await apiClient.get(`${this.baseUrl}/pipelines/${pipelineId}/export`, {
      params: { format }
    });
    return response.data.config;
  }

  // Import pipeline configuration
  async importPipelineConfig(config: string, format: 'yaml' | 'json' = 'yaml'): Promise<PipelineResponse> {
    const response = await apiClient.post(`${this.baseUrl}/import`, {
      config,
      format
    });
    return response.data;
  }

  // Bulk operations
  async bulkEnablePipelines(pipelineIds: string[]): Promise<void> {
    await apiClient.patch(`${this.baseUrl}/pipelines/bulk-enable`, {
      pipeline_ids: pipelineIds
    });
  }

  async bulkDisablePipelines(pipelineIds: string[]): Promise<void> {
    await apiClient.patch(`${this.baseUrl}/pipelines/bulk-disable`, {
      pipeline_ids: pipelineIds
    });
  }

  async bulkDeletePipelines(pipelineIds: string[]): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/pipelines/bulk-delete`, {
      data: { pipeline_ids: pipelineIds }
    });
  }
}

export const cicdService = new CICDService();
export default cicdService;
